
#define EX_SSS_SCP03_FILE_DIR "/tmp/"
#define RESUME_SCP03_FILE_PATH EX_SSS_SCP03_FILE_DIR "resume_scp.txt"

static int saveScp03StateToFile(void)
{
    FILE *fHandle = NULL;

    fHandle = fopen(RESUME_SCP03_FILE_PATH, "wb");

    if (fHandle == NULL) {
        SMLOG_E("Failed to open " RESUME_SCP03_FILE_PATH " for writing\r\n");
        return -1;
    }

    SMLOG_W(
        "Simply writing the session keys to the file system is not a secure implementation. It must not be used in "
        "production !!!...\n");

    fwrite((const void *)scp03_dyn_enc, 16, 1, fHandle);
    fwrite((const void *)scp03_dyn_mac, 16, 1, fHandle);
    fwrite((const void *)scp03_dyn_dek, 16, 1, fHandle);
    fwrite((const void *)scp03_dyn_ctr, 16, 1, fHandle);
    fwrite((const void *)scp03_dyn_mcv, 16, 1, fHandle);
    fclose(fHandle);
    return 0;
}

static int readScp03StateToFile(void)
{
    FILE *fHandle = NULL;

    fHandle = fopen(RESUME_SCP03_FILE_PATH, "rb");

    if (fHandle == NULL) {
        SMLOG_E("Failed to open file " RESUME_SCP03_FILE_PATH " for reading");
        return -1;
    }

    fread((void *)scp03_dyn_enc, 16, 1, fHandle);
    fread((void *)scp03_dyn_mac, 16, 1, fHandle);
    fread((void *)scp03_dyn_dek, 16, 1, fHandle);
    fread((void *)scp03_dyn_ctr, 16, 1, fHandle);
    fread((void *)scp03_dyn_mcv, 16, 1, fHandle);
    fclose(fHandle);
    return 0;
}
