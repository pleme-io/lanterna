{
  description = "lanterna (lantern) — typed observe-only ClickHouse client + MCP server";

  inputs.substrate.url = "github:pleme-io/substrate";

  outputs = { substrate, ... }: substrate.rust.workspace {
    src = ./.;
    member = "lanterna-mcp";
  };
}
