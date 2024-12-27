
rule File_42d47dbdbc1fa55761dad47ec4c0da6c {
    strings:
        $file_hash = "42d47dbdbc1fa55761dad47ec4c0da6c"
    condition:
        $file_hash
}
