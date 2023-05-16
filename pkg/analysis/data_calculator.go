package analysis

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/lockmap"
	"github.com/immune-gmbh/AttestationFailureAnalysisService/pkg/objhash"

	"github.com/facebookincubator/go-belt/tool/logger"
	lru "github.com/hashicorp/golang-lru"
)

// DataCalculator is a handler which resolves missing values for the analyzers using the given values
type DataCalculator struct {
	// valueCalculators is a container for executable functions that can calculate values for certain types
	valueCalculators map[reflect.Type]any // calculator[any, any]

	mu       sync.Mutex
	singleOp *lockmap.LockMap

	// contains all objects that are currently being calculated
	runtime map[objhash.ObjHash]*calculatorFuture
	// cache contains an objhash.ObjHash -> globalCacheItem of calculated values
	cache cacheInterface
}

type cacheInterface interface {
	Get(key any) (value any, ok bool)
	Add(key, value any)
	Len() int
}

type dummyCache struct{}

var _ cacheInterface = (*dummyCache)(nil)

func (dummyCache) Get(key any) (value any, ok bool) {
	return nil, false
}

func (dummyCache) Add(key, value any) {}

func (dummyCache) Len() int {
	return 0
}

// NewDataCalculator creates a new DataCalculator object
func NewDataCalculator(cacheSize int) (*DataCalculator, error) {
	var cache cacheInterface
	if cacheSize > 0 {
		var err error
		cache, err = lru.New2Q(cacheSize)
		if err != nil {
			return nil, fmt.Errorf("failed to create internal cache: %w", err)
		}
	} else {
		cache = dummyCache{}
	}

	dc := &DataCalculator{
		valueCalculators: make(map[reflect.Type]any),
		runtime:          make(map[objhash.ObjHash]*calculatorFuture),
		cache:            cache,
		singleOp:         lockmap.NewLockMap(),
	}

	// valueCalculators should have a check for cyclic dependencies. Currently rely on code review
	if err := SetValueCalculator(dc, getOriginalFirmware); err != nil {
		return nil, err
	}
	if err := SetValueCalculator(dc, getActualFirmware); err != nil {
		return nil, err
	}
	if err := SetValueCalculator(dc, getActualPSPFirmware); err != nil {
		return nil, err
	}
	if err := SetValueCalculator(dc, getFixedRegisters); err != nil {
		return nil, err
	}
	if err := SetValueCalculator(dc, getAlignedOriginalImage); err != nil {
		return nil, err
	}
	if err := SetValueCalculator(dc, getActualBIOSInfo); err != nil {
		return nil, err
	}
	if err := SetValueCalculator(dc, getOriginalBIOSInfo); err != nil {
		return nil, err
	}
	if err := SetValueCalculator(dc, bootFlowUpstreamToDownstream); err != nil {
		return nil, err
	}
	if err := SetValueCalculator(dc, bootFlowDefault); err != nil {
		return nil, err
	}

	return dc, nil
}

// Calculate calculates value of type 't' based on input 'in' argument
func (dc *DataCalculator) Calculate(
	ctx context.Context,
	t reflect.Type,
	in Input,
	cache DataCache,
) (reflect.Value, []Issue, error) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if _, found := dc.valueCalculators[t]; !found {
		return reflect.Value{}, nil, ErrCalcNotSupported{typeName: t.Name()}
	}
	return dc.resolveType(ctx, t, in, cache)
}

type calculator[inputType, outputType any] interface {
	~func(context.Context, inputType) (outputType, []Issue, error)
}

// SetValueCalculator verifies and sets a function "calc" which can compute the values of parameters used as inputs for analyzers.
//
// Note:
// There could be only one calculator for one output type. Setting a calculator for a type where a calculator is already set
// will overwrite the calculator.
//
// TODO: The UNIQUE KEY for calculators should be not the outputType, but inputType+outputType. For example
//
//	BIOSInfo could be calculated from different input types and it should be allowed.
//
// For example: firmware parsing, fixing register's values.
// Input argument should be a function of format func(ctx context.Context, in InputStruct) (Output1, Output2, ..., OutputN, []Issue, error)
func SetValueCalculator[inputType, outputType any, T calculator[inputType, outputType]](dc *DataCalculator, calc T) error {
	calcType := reflect.TypeOf(calc)

	// first check, modify internal state later
	outType := calcType.Out(0)
	if outType.Kind() == reflect.Pointer {
		outType = outType.Elem()
	}
	dc.valueCalculators[outType] = calc
	return nil
}

// resolveType tries to get a value for specific type that should be either provided as input to Executor
// or be calculated using functions provided to addValueCalculator method
func (dc *DataCalculator) resolveType(
	ctx context.Context,
	t reflect.Type,
	in Input,
	cache DataCache,
) (retValue reflect.Value, retIssues []Issue, retErr error) {
	log := logger.FromCtx(ctx)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if res := findType(ctx, t, in, cache); res != nil {
		return res.Val, res.Issues, res.Err
	}

	calculator := dc.valueCalculators[t]
	if calculator == nil {
		return reflect.Value{}, nil, ErrMissingInput{missingType: t.String()}
	}

	// try to calculate the value, but first we should resolve all its dependencies
	calculatorVal := reflect.ValueOf(calculator)
	calculatorType := calculatorVal.Type()
	if calculatorVal.Kind() != reflect.Func {
		panic(fmt.Sprintf("calculator's type for '%s' is not a function", calculatorType))
	}

	inputValue, inputIssues, err := resolveInputStruct(ctx, calculatorType.In(1), in, cache, dc)
	if err != nil {
		return reflect.Value{}, nil, err
	}

	// search in cache
	opHash, err := objhash.Build(fmt.Sprintf("%p", calculator), inputValue.Interface())
	if err != nil {
		return reflect.Value{}, nil, fmt.Errorf("failed to build hash for input of type '%T': %w", inputValue.Interface(), err)
	}

	// We do not want to allow the same calculations being performed from
	// multiple goroutines at the same time. Instead we wait until one of
	// them will end, and then will reuse the result in the rest.
	unlocker := dc.singleOp.Lock(opHash)
	defer unlocker.Unlock()
	if cachedValue, ok := unlocker.UserData.(*CachedValue); ok {
		return cachedValue.Val, cachedValue.Issues, cachedValue.Err
	}
	defer func() {
		unlocker.UserData = &CachedValue{
			Val:    retValue,
			Issues: retIssues,
			Err:    retErr,
		}
	}()

	if cache != nil {
		if res := cache.Get(t, &opHash); res != nil {
			return res.Val, res.Issues, res.Err
		}
	}

	// search in global results cache
	if cached, found := dc.cache.Get(opHash); found {
		item := cached.(*globalCacheItem)
		if v, found := item.values[t]; found {
			log.Debugf("Found result type '%s' and key 0x'%X' in global cache", t, opHash)
			return v, item.issues, nil
		}
	}

	processCalcResult := func(calcResult calculatorResult) (reflect.Value, []Issue, error) {
		if calcResult.err != nil {
			resultErr := ErrFailedCalcInput{Input: t.String(), Err: calcResult.err}
			if cache != nil {
				cache.Set(t, opHash, &CachedValue{Err: resultErr})
			}
			return reflect.Value{}, nil, resultErr
		}

		allIssues := uniqueIssues(append(calcResult.issues, inputIssues...))
		if cache != nil {
			cache.Set(
				t,
				opHash,
				&CachedValue{
					Issues: allIssues,
					Val:    calcResult.value,
				},
			)
		}

		return calcResult.value, allIssues, nil
	}

	// Maybe one has started calculating this value? Look-up in a runtime cache
	calcFuture, found := func() (*calculatorFuture, bool) {
		dc.mu.Lock()
		defer dc.mu.Unlock()

		if result, found := dc.runtime[opHash]; found {
			return result, true
		}

		result := newCalculatorFuture(func() {
			dc.mu.Lock()
			defer dc.mu.Unlock()

			delete(dc.runtime, opHash)
		})
		dc.runtime[opHash] = result
		return result, false
	}()
	if found {
		log.Debugf("Found result type '%s' and key '0x%X' in runtime cache", t, opHash)
		calcResult, err := calcFuture.Get()
		if err != nil {
			return reflect.Value{}, nil, err
		}
		return processCalcResult(*calcResult)
	}

	// We are the first (and probably the only) who requested a value under this circumstances
	inputArgs := prepareInputArgs(ctx, inputValue, calculatorType.In(1).Kind() == reflect.Ptr)
	calcResult, err := newCalculatorResult(calculatorVal.Call(inputArgs))
	if err != nil {
		log.Errorf("failed to process calculator '%s' results: '%v'", calculatorType.Name(), err)
		calcFuture.SetError(err)
		return reflect.Value{}, nil, err
	}
	log.Debugf("Calculated result for type '%s' and key 0x'%X'", t, opHash)

	// do not cache errors in a global cache, as they may disappear (for example someone will fix the orig firmware table)
	if dc.cache != nil && calcResult.err == nil {
		dc.cache.Add(opHash, newGlobalCacheItem(calcResult.value, uniqueIssues(append(calcResult.issues, inputIssues...))))
	}
	calcFuture.SetValue(*calcResult)
	return processCalcResult(*calcResult)
}

type calculatorResult struct {
	value  reflect.Value
	issues []Issue
	err    error
}

func newCalculatorResult(results []reflect.Value) (*calculatorResult, error) {
	return &calculatorResult{
		value:  results[0],
		issues: results[1].Interface().([]Issue),
		err:    convertErrorValue(results[2]),
	}, nil
}

type globalCacheItem struct {
	values map[reflect.Type]reflect.Value
	issues []Issue
}

func newGlobalCacheItem(value reflect.Value, issues []Issue) *globalCacheItem {
	valuesMap := make(map[reflect.Type]reflect.Value)

	// We want to dereference a pointer only if it is a not-nil pointer
	if reflect.Indirect(value).IsValid() {
		value = reflect.Indirect(value)
	}

	// should not save in cache big chunks of data, like parsed firmware.
	// Or very specific/flaky objects
	switch value.Type() {
	case reflect.TypeOf((*BytesBlob)(nil)).Elem():
		break
	case reflect.TypeOf(OriginalFirmware{}), reflect.TypeOf(ActualFirmware{}), reflect.TypeOf(AlignedOriginalFirmware{}), reflect.TypeOf(ActualPSPFirmware{}):
		break
	default:
		valuesMap[value.Type()] = value
	}
	return &globalCacheItem{
		values: valuesMap,
		issues: issues,
	}
}

type calculatorFuture struct {
	onResultSet func()

	mu   sync.Mutex
	cond *sync.Cond

	set bool
	res calculatorResult
	err error
}

func (f *calculatorFuture) Get() (*calculatorResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for {
		if f.set {
			if f.err != nil {
				return nil, f.err
			}
			return &f.res, nil
		}

		f.cond.Wait()
	}
}

func (f *calculatorFuture) SetValue(v calculatorResult) {
	func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.set {
			panic("Future result is already set")
		}

		f.res = v
		f.resultSet()
	}()
	if f.onResultSet != nil {
		f.onResultSet()
	}
}

func (f *calculatorFuture) SetError(err error) {
	if err == nil {
		panic("Argument of SetError() should not be nil")
	}

	func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.set {
			panic("Future result is already set")
		}

		f.err = err
		f.resultSet()
	}()
	if f.onResultSet != nil {
		f.onResultSet()
	}
}

func (f *calculatorFuture) resultSet() {
	f.set = true
	f.cond.Broadcast()
}

func newCalculatorFuture(onResultSet func()) *calculatorFuture {
	result := &calculatorFuture{
		onResultSet: onResultSet,
	}
	result.cond = sync.NewCond(&result.mu)
	return result
}

func prepareInputArgs(ctx context.Context, inputPtr reflect.Value, inputByPtr bool) []reflect.Value {
	inputArgs := []reflect.Value{reflect.ValueOf(ctx)}
	if inputByPtr {
		inputArgs = append(inputArgs, inputPtr)
	} else {
		inputArgs = append(inputArgs, inputPtr.Elem())
	}
	return inputArgs
}

func uniqueIssues(in []Issue) []Issue {
	filtered := make(map[reflect.Value]struct{})
	for _, issue := range in {
		filtered[reflect.ValueOf(issue)] = struct{}{}
	}

	var result []Issue
	for v := range filtered {
		result = append(result, v.Interface().(Issue))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Description < result[j].Description
	})
	return result
}

func convertErrorValue(v reflect.Value) error {
	if v.IsNil() {
		return nil
	}
	return v.Interface().(error)
}

func isOptional(tags []string) bool {
	for _, tag := range tags {
		if tag == "optional" {
			return true
		}
	}
	return false
}
