# crackme7 — Finding the Correct Input (31337) from `main` (Static)

## Objective
Identify the menu input that triggers the hidden `giveFlag()` path by analyzing `main`.

## 1. Determine the Input Type at the Menu Prompt
After printing `"\n[>] "`, the program reads the user choice using:

- `scanf("%u", &var_C)`

Implication:
- The menu expects an **unsigned decimal integer**.
- Any non-numeric input (e.g., `"iz"`) will fail parsing and lead to an error path.

## 2. Map the Visible Menu Branches
The value stored in `var_C` is checked against the documented options:

- `var_C == 1` → "Say hello"
- `var_C == 2` → "Add numbers"
- `var_C == 3` → "Quit"

If the choice is not `1`, `2`, or `3`, execution continues into an additional branch.

## 3. Identify the Hidden Condition
In the non-1/2/3 path, `main` performs a direct comparison:

- `cmp eax, 0x7A69`
- if equal → prints `"Wow such h4x0r!"` and calls `giveFlag()`

So the required condition is:

- `var_C == 0x7A69`

## 4. Convert the Required Constant to Valid Input Format
Because the program uses `scanf("%u")`, the correct input must be **decimal**.

Convert:
- `0x7A69` (hex) → `31337` (decimal)

## Conclusion
At the `[>]` prompt, enter:

- `31337`

This satisfies the hidden comparison (`var_C == 0x7A69`) and triggers `giveFlag()`.
