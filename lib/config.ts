
export interface BaseConfig {
  version: string;
  bits: string;

  sizeOf(structure: string) : number;
  offsetOf(structure: string, field: string) : number;
  offsetStructMember(addr: NativePointer, structure: string, field: string) : NativePointer;
}

