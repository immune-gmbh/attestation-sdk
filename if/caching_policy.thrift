namespace go if.generated.caching_policy

enum CachingPolicy {
  // Default means the server itself may chose the CachingPolicy.
  Default = 0,

  // NoCache forbids server neither to save data into a cache,
  // nor to use data from a cache.
  NoCache = 1,

  // StoreAndUseCache enforces server to save data into a cache, and
  // use data available in the cache.
  StoreAndUseCache = 2,

  // UseCache enforces server to do not save data to a cache, but
  // to use data available in the cache.
  UseCache = 3,
}
