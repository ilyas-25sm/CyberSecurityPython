
rule File_7a74acef1afa2500fece97fc55ee6b35 {
    strings:
        $file_hash = "7a74acef1afa2500fece97fc55ee6b35"
    condition:
        $file_hash
}
