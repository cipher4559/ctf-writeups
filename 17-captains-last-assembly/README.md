# Captain's Last Assembly: Sector 7 Protocol

| | |
|---|---|
| **Challenge ID** | `3wEw7eE7` |
| **Category** | Reverse Engineering |
| **Flag format** | `ICTF{UPPERCASE_LETTERS_AND_UNDERSCORES}` |

## Premise

Deep beneath a decommissioned naval robotics proving ground, the automated
**Sector 7 Protocol** seals Captain Thorne's vault core. Entry requires:

* Level 5 Biometric Authorization, and
* 1,000,000 Clearance Credits.

The terminal's credit replicator dispenses **1 credit per 60 seconds** (≈694 days
of waiting), and a kinetic barrier physically blocks the hallway. There is no
legitimate way in — the compiled game logic must be reversed and the barrier
bypassed.

## Artifact

A Windows Unity build:

```
d5027d56e6104b47801fa0bfe87c7d5d.zip
CaptainsLastAssembly_Data/
  globalgamemanagers
  level0
  Managed/Assembly-CSharp.dll      <- game logic
  ...
CaptainsLastAssembly.exe
```

(`Assembly-CSharp.dll` is the C# assembly containing the game's scripts; everything
else is stock Unity/Mono runtime.)

## Step 1 — decompile the managed assembly

```bash
ilspycmd -o out Assembly-CSharp.dll
```

The interesting types are `FacilitySecurity`, `ActivatePillars`, the `Player`
controller, and `VaultCoreTerminal`. The gate is:

```csharp
public static bool ValidateAccessClearance(int credits, bool biometricConfirmed)
{
    return credits >= RequiredCredits && biometricConfirmed;   // 1,000,000 credits
}
```

`FacilitySecurity.RequestCreditGrant` increments `PlayerCredits` by exactly **1**
every `CooldownSeconds = 60f`, so the legit path really does take ~694 days.

The vault side is:

```csharp
public static class VaultCoreTerminal
{
    public static bool IsVaultBreached = false;
    public static string DecryptedFlag = "";

    private static readonly byte[] EncryptedPayload = new byte[38]
    {
        26, 6, 23, 18, 52, 3, 98, 18, 11, 23,
        1, 2, 13, 116, 28, 9, 15, 29, 28, 27,
        120, 29, 26, 4, 21, 27, 23, 96, 18, 28,
        28, 22, 22, 2, 118, 0, 22, 62
    };

    private static readonly byte[] CipherKey =
        new byte[7] { 83, 69, 67, 84, 79, 82, 55 };   // "SECTOR7"

    public static string DecryptFlag()
    {
        char[] array = new char[EncryptedPayload.Length];
        for (int i = 0; i < EncryptedPayload.Length; i++)
            array[i] = (char)(EncryptedPayload[i] ^ CipherKey[i % CipherKey.Length]);
        return new string(array);
    }

    public static bool CheckProximity(Vector3 pos)
        => pos.z > 17.5f || pos.x > 14f || pos.y > 10f;

    public static void TriggerBreach() { IsVaultBreached = true; /* logs DecryptFlag() */ }
}
```

The `Player` controller calls `TriggerBreach` from `CheckVaultZone` whenever the
player is not yet in the vault room but crosses the zone boundary:

```csharp
if (!inVaultRoom && (transform.position.z > 17.5f || VaultCoreTerminal.CheckProximity(transform.position)))
{
    inVaultRoom = true;
    VaultCoreTerminal.TriggerBreach();
}
```

There is also a **diagnostic noclip mode** (`player.enableNoclip`) exposed in the
HUD: fly through the kinetic barrier into the vault zone and `TriggerBreach` runs
without ever meeting the credit requirement. Equivalent static solutions are to
patch `IsVaultBreached`, `PlayerCredits`, or `ValidateAccessClearance` in the
assembly ("ASSEMBLY OVERRIDE" is literally the message the game prints).

## Step 2 — decrypt

`EncryptedPayload` XOR `"SECTOR7"` (the key bytes `83, 69, 67, 84, 79, 82, 55`),
cycling every 7 bytes:

```python
enc = [26, 6, 23, 18, 52, 3, 98, 18, 11, 23, 1, 2, 13, 116,
       28, 9, 15, 29, 28, 27, 120, 29, 26, 4, 21, 27, 23, 96,
       18, 28, 28, 22, 22, 2, 118, 0, 22, 62]
key = b"SECTOR7"

print("".join(chr(b ^ key[i % len(key)]) for i, b in enumerate(enc)))
```

Output:

```
ICTF{QUANTUM_COLLISION_GATEWAY_BYPASS}
```

## Why "Sector 7"?

The XOR key `SECTOR7` is the level's own name. The credit grind and the kinetic
barrier are deliberate time-wasters: the vault condition (`TriggerBreach`) is
reachable by position alone, and the flag is a hard-coded ciphertext sitting next
to its key in managed code.

## Tools & Methodology

**Tools:** `ilspycmd` (dnSpy as backup), `strings`, Python 3 (XOR), .NET
assembly inspection.

**Method:**

1. Decompiled `Assembly-CSharp.dll` with `ilspycmd` and read `FacilitySecurity`,
   `ActivatePillars`, and `VaultCoreTerminal`.
2. Confirmed the legitimate credit gate was infeasible (1 credit per 60 s) and
   focused on the static `EncryptedPayload`.
3. XORed the 38-byte payload with `SECTOR7`, recovered `ICTF{...}`, and verified
   the key against the decompiled code.

## Flag

```
ICTF{QUANTUM_COLLISION_GATEWAY_BYPASS}
```

## Takeaway

Unity games ship their logic as a plain .NET assembly
(`Assembly-CSharp.dll`); tools like `ilspycmd`, `dnSpy`, or `ILSpy` recover
near-original C#. Gameplay-based obstacles (credit grind, physical barriers) mean
nothing once you can read the assembly: the "vault" is just a method call, and the
"encryption" is a repeating-key XOR with the level name. Static RE beats 694 days
of waiting.
