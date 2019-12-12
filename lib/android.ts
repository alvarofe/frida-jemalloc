import * as utils from "./utils";
import { BaseConfig } from "./config";

const configs: BaseConfigAndroid[] = [];

interface IOffset {
  [field : string] : number
}

interface IStructure {
  [structure: string] : IOffset;
}

export function getAndroidConfig() : BaseConfig {
  let chunkSize = utils.addressSymbols(["je_chunksize", "chunksize"]).readU64();
  let mapMiscOffset = utils.addressSymbols(["je_map_misc_offset"]).readU64();
  let version;
  let bits;

  // Add more configs
  configs.push(new Android864());

  if (chunkSize.equals(0x80000)) {
    bits = "32";
    if (mapMiscOffset.equals(0x230)) {
      version = "8";
    } else if (mapMiscOffset.equals(0x228)) {
      version = "7";
    }
  } else if (chunkSize.equals(0x200000)) {
    bits = "64";
    if (mapMiscOffset.equals(0x1010)) {
      version = "8";
    } else if (mapMiscOffset.equals(0x1008)) {
      version = "7";
    }
  } else if (chunkSize.equals(0x40000)) {
    version = "6";
    if (utils.dwordSize === 4) {
      bits = "32";
    } else if (utils.dwordSize === 8) {
      bits = "64";
    }
  } else {
    return null;
  }

  for (var i = 0; i < configs.length; i++) {
    if (configs[i].version === version && configs[i].bits === bits) {
      return configs[i];
    }
  }
}

class BaseConfigAndroid implements BaseConfig {
  version: string;
  bits: string;
  values : IOffset;
  sizes: IOffset;
  offsets : IStructure;

  public sizeOf(structure: string) : number {
    if (structure in this.sizes) {
      return this.sizes[structure];
    }
    return 0;
  }

  public offsetOf(structure: string, field: string) : number {
    if (structure in this.offsets) {
      if (field in this.offsets[structure]) {
        return this.offsets[structure][field];
      }
    }

    return 0;
  }

  public offsetStructMember(addr: NativePointer, structure: string, field: string) : NativePointer {
    return addr.add(this.offsetOf(structure, field));
  }
}

class Android864 extends BaseConfigAndroid {
  version: string = "8";
  bits: string = "64";
  values : IOffset;
  sizes: IOffset;
  offsets : IStructure;

  constructor() {
    super();
    // Init values
    this.values = {};
    this.values['narenas_total'] = 2;
    this.values['je_maps_bias'] = 2;
    this.values['je_nhbins'] = 0x30;
    this.values['je_map_misc_offset'] = 0x228;
    this.values['je_chunksize'] = 0x80000;

    // Init sizes
    this.sizes = {};
    this.sizes['pthread_key_data_t'] = 0x10;
    this.sizes['arena_run_t'] = 0x48;
    this.sizes['arena_chunk_map_bits_t'] = 0x8;
    this.sizes['rtree_level_t'] = 0x10;
    this.sizes['arena_bin_info_t'] = 0x40;
    this.sizes['rtree_t'] = 0x68;
    this.sizes['arena_bin_t'] = 0xa8;
    this.sizes['arena_chunk_map_misc_t'] = 0x60;
    this.sizes['pthread_internal_t'] = 0xb08;
    this.sizes['tcache_bin_t'] = 0x20;

    // Init offsets
    this.offsets = {};
    this.offsets['arena_bin_info_t'] = {};
    this.offsets['arena_bin_info_t']['reg0_offset'] = 0x38;
    this.offsets['arena_bin_info_t']['run_size'] = 0x18;
    this.offsets['arena_bin_info_t']['reg_size'] = 0x0;
    this.offsets['arena_bin_info_t']['nregs'] = 0x20;

    this.offsets['arena_bin_t'] = {};
    this.offsets['arena_bin_t']['runcur'] = 0x50;

    this.offsets['arena_chunk_t'] = {};
    this.offsets['arena_chunk_t']['map_bits'] = 0x78;
    this.offsets['arena_chunk_t']['node'] = 0x0;

    this.offsets['arena_chunk_map_bits_t'] = {};
    this.offsets['arena_chunk_map_misc_t'] = {};
    this.offsets['arena_chunk_map_bits_t']['bits'] = 0x0;
    this.offsets['arena_chunk_map_misc_t']['run'] = 0x18;

    this.offsets['rtree_t'] = {};
    this.offsets['rtree_t']['height'] = 0x10;
    this.offsets['rtree_t']['levels'] = 0x28;

    this.offsets['rtree_level_t'] = {};
    this.offsets['rtree_level_t']['bits'] = 0x8;
    this.offsets['rtree_level_t']['subtree'] = 0x0;

    this.offsets['pthread_key_data_t'] = {};
    this.offsets['pthread_internal_t'] = {};
    this.offsets['pthread_key_data_t']['data'] = 0x8;
    this.offsets['pthread_internal_t']['tid'] = 0x10;
    this.offsets['pthread_internal_t']['key_data'] = 0xe0;
    this.offsets['pthread_internal_t']['next'] = 0x0;

    this.offsets['arena_t'] = {};
    this.offsets['arena_t']['bins'] = 0x980;

    this.offsets['arena_run_t'] = {};
    this.offsets['arena_run_t']['nfree'] = 0x4;
    this.offsets['arena_run_t']['bitmap'] = 0x8;

    this.offsets['extent_node_t'] = {};
    this.offsets['extent_node_t']['en_addr'] = 0x8;
    this.offsets['extent_node_t']['en_arena'] = 0x0;

    this.offsets['tcache_bin_t'] = {};
    this.offsets['tcache_bin_t']['lg_fill_div'] = 0xc;
    this.offsets['tcache_bin_t']['low_water'] = 0x8;
    this.offsets['tcache_bin_t']['ncached'] = 0x10;
    this.offsets['tcache_bin_t']['avail'] = 0x18;

    this.offsets['tcache_t'] = {};
    this.offsets['tcache_t']['tbins'] = 0x28;
  }
}

