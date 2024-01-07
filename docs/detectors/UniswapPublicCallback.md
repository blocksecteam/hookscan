# UniswapPublicCallback

## Info

**Spec**

- Severity: High
- Confidence: High

**Description**

Callers of callback functions are not exclusively restricted to the contract itself.

## Sample

```diff
abstract contract BaseHook is IHooks {
    modifier selfOnly() {
        if (msg.sender != address(this)) revert NotSelf();
        _;
    }
}

contract Hook is BaseHook {
    uint count;

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {}

    function foo() external {
        poolManager.lock(abi.encodeWithSignature("callback()"));
    }

-    function callback() external {
+    function callback() external selfOnly {
        count++;
    }
}
```

For any callback functions that are called by lockAcquired using external calls, there should be an only-self check (no need for internal callback).
