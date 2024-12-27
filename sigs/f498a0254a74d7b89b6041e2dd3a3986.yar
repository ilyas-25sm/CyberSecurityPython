
rule File_f498a0254a74d7b89b6041e2dd3a3986 {
    strings:
        $file_hash = "f498a0254a74d7b89b6041e2dd3a3986"
    condition:
        $file_hash
}
