import * as utils from "./utils";
import * as config from "./config";

export function detectAndroidVersion() : config.BaseConfigAndroid {
  let chunksize = utils.addressSymbols(["je_chunksize", "chunksize"]).readU64();
  let map_misc_offset = utils.addressSymbols(["je_map_misc_offset"]).readU64();
  let version;
  let bits;

  config.initConfigAndroid();

  if (chunksize.equals(0x80000)) {
    bits = "32";
    if (map_misc_offset.equals(0x230)) {
      version = "8";
    } else if (map_misc_offset.equals(0x228)) {
      version = "7";
    }
  } else if (chunksize.equals(0x200000)) {
    bits = "64";
    if (map_misc_offset.equals(0x1010)) {
      version = "8";
    } else if (map_misc_offset.equals(0x1008)) {
      version = "7";
    }
  } else if (chunksize.equals(0x40000)) {
    version = "6";
    if (utils.dword_size === 4) {
      bits = "32";
    } else if (utils.dword_size === 8) {
      bits = "64";
    }
  }

  return config.getConfig(version, bits);
}

