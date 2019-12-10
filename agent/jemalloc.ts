import * as utils from  "./utils";
import * as cfg from "./config";

class BinInfo {
  reg_size: number;
  run_size: number;
  reg0_off: number;
  nregs: number;

  constructor(reg_size: number, run_size: number, reg0_off: number, nregs: number) {
    this.reg_size = reg_size;
    this.run_size = run_size;
    this.reg0_off = reg0_off;
    this.nregs = nregs;
  }
}

export class Jemalloc {
  nbins: number;
  android: cfg.BaseConfigAndroid;
  bin_info: BinInfo[] = [];

  constructor(config : cfg.BaseConfigAndroid) {
    this.android = config;
    this.nbins = <number> utils.calculateNBins();
  }

  parse_bin_info() {
    const info_addr = utils.addressSymbols(["je_arena_bin_info"]);
    console.log("[*] Parsing arena_bin_info array");
  }
}
