# UniswapPublicHook

## Info

**Spec**

- Severity: High
- Confidence: High

**Description**

Callers of hook functions are not exclusively restricted to the pool manager alone.

## Sample

```diff
abstract contract BaseHook is IHooks {
    IPoolManager public immutable poolManager;

    constructor(IPoolManager _poolManager) {
        poolManager = _poolManager;
    }

    modifier poolManagerOnly() {
        if (msg.sender != address(poolManager)) revert NotPoolManager();
        _;
    }
}

contract Hook is BaseHook {
    uint count;

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {}

    function beforeSwap(
        address,
        PoolKey calldata,
        IPoolManager.SwapParams calldata,
        bytes calldata
-    ) external override returns (bytes4) {
+    ) external override poolManagerOnly returns (bytes4) {
        count++;  // make changes to contract states
        return IHooks.beforeSwap.selector;
    }
}
```

This detector enumerates all the hook functions (e.g. `beforeSwap`) that are not `view` (i.e., read only) and can be called by anyone without privilege validation.
