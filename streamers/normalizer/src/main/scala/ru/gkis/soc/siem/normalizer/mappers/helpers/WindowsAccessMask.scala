package ru.gkis.soc.siem.normalizer.mappers.helpers

object WindowsAccessMask {

    /*
        https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663

        -------<<< position <<<---------
        33222222222211111111110000000000
        10987654321098765432109876543210

        10000000000000000000000000000000   <-- READ
        01000000000000000000000000000000   <-- WRITE
        00100000000000000000000000000000   <-- APPEND
        00010000000000000000000000000000   <-- READ_EXT_ATTR
        00001000000000000000000000000000   <-- WRITE_EXT_ATTR
        00000100000000000000000000000000   <-- EXECUTE
        00000010000000000000000000000000   <-- DELETE_DIR
        00000001000000000000000000000000   <-- READ_ATTR
        00000000100000000000000000000000   <-- WRITE_ATTR
        00000000000000001000000000000000   <-- DELETE
        00000000000000000100000000000000   <-- READ_SACL
        00000000000000000010000000000000   <-- CHMOD
        00000000000000000001000000000000   <-- CHOWN
        00000000000000000000100000000000   <-- SYNC
        00000000000000000000000010000000   <-- WRITE_SACL
     */

    val READ: Int           = 0x1         // ReadData, ListDirectory
    val WRITE: Int          = 0x2         // WriteData, AddFile
    val APPEND: Int         = 0x4         // AppendData, AddSubdirectory, CreatePipeInstance
    val READ_EXT_ATTR: Int  = 0x8         // extended file attributes
    val WRITE_EXT_ATTR: Int = 0x10        // write extended file attributes
    val EXECUTE: Int        = 0x20        // Execute, Traverse
    val DELETE_DIR: Int     = 0x40        // delete a directory and all the files it
    val READ_ATTR: Int      = 0x80        // read file attributes
    val WRITE_ATTR: Int     = 0x100       // write file attributes
    val DELETE: Int         = 0x10000     // delete the object
    val READ_SACL: Int      = 0x20000     // read the information in the object's security descriptor
    val CHMOD: Int          = 0x40000     // modify the discretionary access control list
    val CHOWN: Int          = 0x80000     // change the owner
    val SYNC: Int           = 0x100000    // use the object for synchronization
    val WRITE_SACL: Int     = 0x1000000   // get or set the SACL

    def permissionSet(acl: Int, permission: Int): Boolean = (acl & permission) != 0

}
