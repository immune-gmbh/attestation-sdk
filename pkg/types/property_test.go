package types

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/stretchr/testify/require"
)

type propertiesFromFlowTestCase struct {
	Flow               pcr.Flow
	ExpectedProperties Properties
	StatusRegisters    registers.Registers
}

func (s Properties) sort() {
	sort.Slice(s, func(i, j int) bool {
		return reflect.TypeOf(s[i]).String() < reflect.TypeOf(s[j]).String()
	})
}

func TestProperties(t *testing.T) {
	t.Run("FlowAuto", func(t *testing.T) {
		// For "FlowAuto" properties are undefined. It is required to use
		// functions "pcr.Detect*Flow" before calling "PropertiesFromFlow".
		props, err := PropertiesFromFlow(pcr.FlowAuto, nil)
		require.Nil(t, props)
		require.Error(t, err)
	})

	for _, testCase := range []propertiesFromFlowTestCase{
		{
			Flow:               pcr.FlowIntelLegacyTXTDisabled,
			ExpectedProperties: Properties{PropertyIntelTXT(false)},
		},
		{
			Flow: pcr.FlowIntelLegacyTXTEnabled,
			ExpectedProperties: Properties{
				PropertyIntelTXT(true),
				PropertyTPMVersion{Major: 2, Minor: 0},
			},
		},
		{
			Flow: pcr.FlowIntelLegacyTXTEnabledTPM12,
			ExpectedProperties: Properties{
				PropertyIntelTXT(true),
				PropertyTPMVersion{Major: 1, Minor: 2},
			},
		},
		{
			Flow: pcr.FlowIntelCBnT0T,
			ExpectedProperties: Properties{
				PropertyIntelTXT(true),
				PropertyTPMVersion{Major: 2, Minor: 0},
				PropertyIntelDCD(true),
				PropertyIntelDBI(false),
			},
			StatusRegisters: registers.Registers{registers.ACMPolicyStatus(1 << 9)},
		},
		{
			Flow: pcr.FlowIntelCBnT0T,
			ExpectedProperties: Properties{
				PropertyIntelTXT(true),
				PropertyTPMVersion{Major: 2, Minor: 0},
				PropertyIntelDCD(false),
				PropertyIntelDBI(true),
			},
			StatusRegisters: registers.Registers{registers.ACMPolicyStatus(1 << 10)},
		},
		{
			Flow: pcr.FlowAMDLocality3,
			ExpectedProperties: Properties{
				PropertyAMDPlatformSecurityProcessor(true),
				PropertyTPMVersion{Major: 2, Minor: 0},
			},
		},
		{
			Flow: pcr.FlowAMDLocality3,
			ExpectedProperties: Properties{
				PropertyAMDPlatformSecurityProcessor(true),
				PropertyAMDPlatformSecureBoot(false),
				PropertyTPMVersion{Major: 2, Minor: 0},
			},
			StatusRegisters: registers.Registers{registers.ParseMP0C2PMsg37Register(0)},
		},
		{
			Flow: pcr.FlowAMDLocality3,
			ExpectedProperties: Properties{
				PropertyAMDPlatformSecurityProcessor(true),
				PropertyAMDPlatformSecureBoot(true),
				PropertyTPMVersion{Major: 2, Minor: 0},
			},
			StatusRegisters: registers.Registers{registers.ParseMP0C2PMsg37Register(0xffffffff)},
		},
	} {
		t.Run(fmt.Sprintf("flow_%s_registers_%v", testCase.Flow.String(), testCase.StatusRegisters), func(t *testing.T) {
			require.NoError(t, testCase.ExpectedProperties.Validate())

			props, err := PropertiesFromFlow(testCase.Flow, testCase.StatusRegisters)
			require.NoError(t, err)
			require.NoError(t, props.Validate())

			testCase.ExpectedProperties.sort()
			props.sort()
			require.Equal(t, testCase.ExpectedProperties, props)

			require.True(t, testCase.ExpectedProperties.ContainsAll(props...))
			props = append(props, props[0])
			require.True(t, testCase.ExpectedProperties.ContainsAll(props...))

			require.True(t, props.ContainsType(testCase.ExpectedProperties[0]))
			require.False(t, testCase.ExpectedProperties.ContainsType(Property(nil)))
		})
	}
}

func TestPropertiesBrokenValidation(t *testing.T) {
	brokenProperties := []Properties{
		{
			PropertyIntelTXT(true),
			PropertyIntelTXT(false),
		},
		{
			PropertyTPMVersion{Major: 2, Minor: 0},
			PropertyTPMVersion{Major: 1, Minor: 2},
		},
		{
			PropertyIntelDCD(true),
			PropertyIntelDCD(false),
		},
		{
			PropertyIntelDBI(true),
			PropertyIntelDBI(false),
		},
		{
			PropertyIntelTXT(true),
			PropertyAMDPlatformSecureBoot(true),
		},
	}

	for _, props := range brokenProperties {
		require.Error(t, props.Validate())
	}
}

func TestDuplicatePropertiesValidation(t *testing.T) {
	props := Properties{
		PropertyIntelTXT(true),
		PropertyIntelTXT(true),
		PropertyTPMVersion{Major: 2, Minor: 0},
		PropertyTPMVersion{Major: 2, Minor: 0},
		PropertyIntelDCD(false),
		PropertyIntelDCD(false),
		PropertyIntelDBI(true),
		PropertyIntelDBI(true),
	}
	require.NoError(t, props.Validate())
}

func TestPropertiesFindByType(t *testing.T) {
	props := Properties{
		PropertyIntelTXT(true),
		PropertyTPMVersion{Major: 2, Minor: 0},
		PropertyIntelDCD(false),
	}

	intelTXT := props.FindByType(PropertyIntelTXT(false))
	require.Equal(t, PropertyIntelTXT(true), intelTXT)

	require.Nil(t, props.FindByType(PropertyIntelDBI(false)))
}
