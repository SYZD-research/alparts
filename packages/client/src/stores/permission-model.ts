export function hasCombinedPermission(permissionValues: string[], required: number): boolean {
  let combined = 0n;
  for (const value of permissionValues) {
    try {
      combined |= BigInt(value);
    } catch {
      // Malformed permission data grants nothing.
    }
  }
  const requiredBits = BigInt(required);
  return (combined & requiredBits) === requiredBits;
}
