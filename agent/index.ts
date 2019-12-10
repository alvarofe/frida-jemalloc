import * as android from "./android";
import * as utils from "./utils";
import {Jemalloc} from "./jemalloc";

utils.collectSymbols();
const jemalloc = new Jemalloc(android.detectAndroidVersion());

jemalloc.parse_bin_info();
