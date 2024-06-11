// Run as: PRIVATE_KEY=<YOUR_PRIV_KEY_WITH_FUNDS> STYLUS_ADDRESS=<YOUR_STYLUS_ADDRESS> npx ts-node src/testk256.ts

import { Hex, parseAbi } from "viem";
import { getPublicClient } from "./common";

async function main() {
  const data = await getPublicClient().readContract({
    address: (process.env.STYLUS_ADDRESS as Hex) || "0x0",
    abi: parseAbi([
      "function hdKeyDerive(bytes data) external returns (bytes)",
    ]),
    functionName: "hdKeyDerive",
    args: [
      "0100000020fdb545b1b3d125d517148099c3403c7b1dd3f4cf3b012522afb7d12d07ba0b130000002b4c49545f48445f4b45595f49445f4b3235365f584d443a5348412d3235365f535357555f524f5f4e554c5f0000000a028506cbedca1d12788d6bc74627d99263c93204d2e9565d861b7c1270736b007102a89cb5090c0aaee9c5831df939abbeab2e0f62b5d54ceae6e816a9fe87c8ca32033e0c9d93b41414c3a8d287bb40ab024fbf176cb45c6616a3bf74e97bb68b516503a0c18f5d9db21fec597edef52f7a26449cdd90357532704a1ede6c27981a31b802794db35a0b6a6968ba4ed059630d788d591f083778dac9a45935549ca5f75ea603b398a663086dc7f1b5948d2195b176a7705fe71b0ad07110f57975254e6015980215f2cddeb89428f74132a84acf7e1a344f2ed9a39768f7006c9b8843e513dc550297d2a91f5a52e98873b7a4946c47d7736d6661cebace9c160d955999be97149203d2ee101c65ca0d60b5bc27ca1859c968984b1096d742874649bdc4fac6e9498a02bb0deb45aefb171e7117390991c2a230218fda04d9bb3cfd343f56ab61c3e390",
    ],
  });
  console.log("data", data);
}

main();
