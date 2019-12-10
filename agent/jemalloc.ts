import * as utils from  "./utils";
import * as cfg from "./config";

class BinInfo {
  reg_size: UInt64;
  run_size: UInt64;
  reg0_off: number;
  nregs: number;

  constructor(reg_size: UInt64, run_size: UInt64, reg0_off: number, nregs: number) {
    this.reg_size = reg_size;
    this.run_size = run_size;
    this.reg0_off = reg0_off;
    this.nregs = nregs;
  }
}

class Chunk {
  addr: NativePointer;
  arena_addr: NativePointer;
  runs = [];

  constructor(addr: NativePointer, arena_addr: NativePointer, runs: []) {
    this.addr = addr;
    this.arena_addr = arena_addr;
    this.runs = runs;
  }
}

export class Jemalloc {
  nbins: number;
  android: cfg.BaseConfigAndroid;
  bin_info: BinInfo[] = [];
  chunks: Chunk[] = [];
  arenas_addr: NativePointer[] = [];

  constructor(config : cfg.BaseConfigAndroid) {
    this.android = config;
    this.nbins = <number> utils.calculateNBins();
  }

  parse_all() {
    this.parse_bin_info();
    this.parse_chunks();
  }

  parse_bin_info() {
    let info_addr = utils.addressSymbols(["je_arena_bin_info"]);
    const info_size = this.android.sizeof("arena_bin_info_t");

    console.log("[*] Parsing arena_bin_info array");

    for (var i = 0; i < this.nbins; i++) {
      const reg_size = this.android.readStructMember(info_addr, "arena_bin_info_t", "reg_size").readU64();
      const run_size = this.android.readStructMember(info_addr, "arena_bin_info_t", "run_size").readU64();
      const reg0_off = this.android.readStructMember(info_addr, "arena_bin_info_t", "reg0_offset").readU32();
      const nregs = this.android.readStructMember(info_addr, "arena_bin_info_t", "nregs").readU32();

      this.bin_info.push(new BinInfo (reg_size, run_size, reg0_off, nregs));

      info_addr = info_addr.add(info_size);
    }
  }

  parse_chunks () {
    const chunks_rtree_addr = utils.addressSymbols(["je_chunks_rtree"]);
    const max_height = this.android.readStructMember(chunks_rtree_addr, "rtree_t", "height").readU32();
    const levels_addr = chunks_rtree_addr.add(this.android.offsetof("rtree_t", "levels"));
    const rtree_levels_size = this.android.sizeof("rtree_level_t");
    let root;
    let stack = [];

    let lvl_addr = levels_addr;
    for (var i = 0; i < max_height; i++) {
      const addr = this.android.readStructMember(lvl_addr, "rtree_level_t", "subtree").readPointer();
      if (addr.equals(0)) {
        lvl_addr = lvl_addr.add(rtree_levels_size);
        continue;
      }

      root = [addr, i];
      break;
    }

    stack.push(root);

    while (stack.length > 0) {
      let element = stack.pop();
      let node = element[0];
      const height = element[1];

      const cur_level_addr = levels_addr.add(height * rtree_levels_size);
      const bits = cur_level_addr.add(this.android.offsetof("rtree_level_t", "bits")).readU32();
      const max_key = 1 << bits;

      for (let i = 0; i < max_key; i++) {
        const addr = node.readPointer();
        let exists = false;
        node = node.add(8);

        if (addr.equals(0))
          continue;

        if (height === max_height - 1) {
          const node_addr = addr.add(this.android.offsetof("arena_chunk_t", "node"));
          const arena_addr = node_addr.add(this.android.offsetof("extent_node_t", "en_arena")).readPointer();

          if (this.arenas_addr.indexOf(arena_addr) != -1) {
            exists = true;
          }

          if (<number><unknown> addr & 0xfff) {
            continue;
          }

          if (exists) {
            this.chunks.push(new Chunk(addr, arena_addr, []));
          } else {
            this.chunks.push(new Chunk(addr, ptr(0), []));
          }
        } else {
          stack.push([addr, height + 1]);
        }
      }
    }
  }
}
