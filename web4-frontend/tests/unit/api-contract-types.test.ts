import { describe, expect, expectTypeOf, it } from "vitest";

import type { HeightCheckedAt } from "../../lib/api-contract/types";
import { checkedAtSchema } from "../../lib/api-contract/schemas";

describe("api-contract checkedAt type contract", () => {
  it("keeps non-negative height markers aligned between zod and TypeScript", () => {
    const zeroHeight: HeightCheckedAt = "height:0";
    const positiveHeight: HeightCheckedAt = "height:42";

    expect(zeroHeight).toBe("height:0");
    expect(positiveHeight).toBe("height:42");
    expect(() => checkedAtSchema.parse("height:-1")).toThrow();
    expect(checkedAtSchema.parse("height:42")).toBe("height:42");

    type NegativeHeight = Extract<HeightCheckedAt, `height:-${string}`>;
    expectTypeOf<NegativeHeight>().toEqualTypeOf<never>();
  });
});
