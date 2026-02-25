import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatusCard } from "./StatusCard";

describe("StatusCard", () => {
  it("renders label and value", () => {
    render(<StatusCard label="Hosts" value="42" status="ok" />);
    expect(screen.getByText("Hosts")).toBeDefined();
    expect(screen.getByText("42")).toBeDefined();
  });

  it("renders pending state with dashes", () => {
    render(<StatusCard label="Vulns" value="--" status="pending" />);
    expect(screen.getByText("Vulns")).toBeDefined();
    expect(screen.getByText("--")).toBeDefined();
  });
});
