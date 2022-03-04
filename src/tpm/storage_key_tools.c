/**
 * @file  storage_key_tools.c
 *
 * @brief Implements library of TPM 2.0 utility functions for managing and
 *        interacting with Kmyth TPM keys (i.e., storage root key and storage
 *        keys).
 */

#include "storage_key_tools.h"

#include <string.h>

#include <arpa/inet.h>
#include <openssl/evp.h>

#include "defines.h"
#include "object_tools.h"
#include "tpm2_interface.h"

//############################################################################
// get_srk_handle()
//############################################################################
int get_srk_handle(TSS2_SYS_CONTEXT * sapi_ctx,
                   TPM2_HANDLE * srk_handle,
                   TPM2B_AUTH * storage_hierarchy_auth)
{
  // Get the list of objects in TPM persistent storage and check them all
  // against the SRK criteria. Upon return from get_existing_srk_handle(),
  // the srk_handle parameter passed to get_existing_srk_handle() is either
  // zero (none of the loaded objects is the SRK) or contains the handle used
  // to reference the SRK in TPM persistent storage. The function
  // get_existing_srk_handle() will set next_persistent_handle to the next
  // available TPM persistent storage location where the SRK can be put.
  TPM2_HANDLE next_persistent_handle = 0;

  if (get_existing_srk_handle(sapi_ctx, srk_handle, &next_persistent_handle))
  {
    kmyth_log(LOG_ERR, "error retrieving SRK handle from TPM ... exiting");
    return 1;
  }

  // If we reach here and the srk_handle value is still zero (empty handle),
  // a handle referencing the SRK is not already loaded in persistent storage.
  // Therefore, we must re-derive it from its seed and load it at the
  // previously determined next available persistent handle
  if (*srk_handle == 0)
  {
    *srk_handle = next_persistent_handle;
    if (put_srk_into_persistent_storage(sapi_ctx,
                                        *srk_handle, *storage_hierarchy_auth))
    {
      kmyth_log(LOG_ERR, "error reinstalling SRK in TPM ... exiting");
      return 1;
    }
  }

  return 0;
}

//############################################################################
// get_existing_srk_handle()
//############################################################################
int get_existing_srk_handle(TSS2_SYS_CONTEXT * sapi_ctx,
                            TPM2_HANDLE * srkHandle,
                            TPM2_HANDLE * nextSrkHandle)
{
  // Set SRK handle value to zero (empty handle). If the SRK is not loaded,
  // we will return this value.
  *srkHandle = 0;

  if (sapi_ctx == NULL)
  {
    kmyth_log(LOG_ERR, "SAPI context not initialized ... exiting");
    return 1;
  }

  // Check to see if the SRK is already in persistent memory by:
  //
  //   1. Getting a list of all persistent objects
  //
  //   2. Searching list for the SRK
  //
  //   3. Computing the next available persistent storage handle.
  //      This is accomplished by retrieving the TPM2_PT_HR_PERSISTENT_AVAIL
  //      property from the TPM, which provides an estimated number of
  //      additional objects that could be loaded into the TPM's non-volatile
  //      memory. If the value is at least one, then at least one object of
  //      any type may be made persistent. While this handle is intended to
  //      be used for a re-derived SRK, for API safety, a valid next handle
  //      is provided whether or not the SRK is found to already be in
  //      persistent storage.
  //

  // Step 1:  Get the list of persistent handles currently loaded into TPM
  //
  //          Note: At the time this was written, TPM2_MAX_CAP_HANDLES=254.
  //                If more than 254 persistent handles were to exist, the
  //                get_tpm2_properties() call would return partial data.
  //                As this limit seems to be much more than the TPM
  //                hardware is expected to support, for now, this seems
  //                an acceptable assumption.

  TPMS_CAPABILITY_DATA persistent_handle_list;

  if (get_tpm2_properties(sapi_ctx,
                          TPM2_CAP_HANDLES,
                          TPM2_HR_PERSISTENT,
                          TPM2_MAX_CAP_HANDLES, &persistent_handle_list))
  {
    kmyth_log(LOG_ERR, "error getting list of persistent handles ... exiting");
    return 1;
  }

  // Step 2:  Search the list for the SRK

  if (persistent_handle_list.data.handles.count == 0)
  {
    kmyth_log(LOG_DEBUG, "no handles for existing persistent objects found");
  }
  else
  {
    kmyth_log(LOG_DEBUG, "checking %d persistent data handle(s) for SRK",
              persistent_handle_list.data.handles.count);
  }

  for (int i = 0; i < persistent_handle_list.data.handles.count; i++)
  {
    bool SRK_flag = false;

    if (check_if_srk(sapi_ctx,
                     persistent_handle_list.data.handles.handle[i], &SRK_flag))
    {
      kmyth_log(LOG_ERR,
                "error checking if handle = 0x%08X references SRK ... exiting",
                persistent_handle_list.data.handles.handle[i]);
      return 1;
    }
    if (SRK_flag)
    {
      *srkHandle = persistent_handle_list.data.handles.handle[i];
      kmyth_log(LOG_DEBUG, "SRK found ... done searching");
      break;
    }
  }

  // Step 3:  Find next available persistent storage handle

  TPMS_CAPABILITY_DATA property_list;

  if (get_tpm2_properties(sapi_ctx,
                          TPM2_CAP_TPM_PROPERTIES,
                          TPM2_PT_HR_PERSISTENT_AVAIL,
                          TPM2_MAX_TPM_PROPERTIES, &property_list))
  {
    kmyth_log(LOG_ERR, "error getting TPM properties ... exiting");
    return 1;
  }

  // first property in returned list should be TPM2_PT_HR_PERSISTENT_AVAIL
  uint32_t ptype = property_list.data.tpmProperties.tpmProperty[0].property;
  uint32_t pval = property_list.data.tpmProperties.tpmProperty[0].value;

  if (ptype != TPM2_PT_HR_PERSISTENT_AVAIL)
  {
    kmyth_log(LOG_ERR, "retrieved unexpected (0x%08X) property ... exiting",
              ptype);
    return 1;
  }
  if (pval <= 0)
  {
    kmyth_log(LOG_WARNING, "TPM cannot support additional persistent objects");
    *nextSrkHandle = 0;         // set to "empty handle"
  }
  else
  {
    kmyth_log(LOG_DEBUG, "TPM supports %u (est) additional persistent objects",
              pval);

    // step through persistent handles until an unused one is found
    // (if persistent handle list empty, first handle in range is available)
    *nextSrkHandle = TPM2_PERSISTENT_FIRST; // 0x81000000 
    bool avail_handle_found = false;

    while ((*nextSrkHandle < TPM2_PLATFORM_PERSISTENT) && (!avail_handle_found))
    {
      bool handleInUse = false;

      for (int i = 0; i < persistent_handle_list.data.handles.count; i++)
      {
        if (*nextSrkHandle == persistent_handle_list.data.handles.handle[i])
        {
          handleInUse = true;   // handle being checked is "in use" (on list)
          break;                // no need to compare with other handles in list
        }
      }
      if (!handleInUse)
      {
        // found available handle
        avail_handle_found = true;
      }
      else
      {
        // handle just checked was in use -- prepare to check next one
        *nextSrkHandle = *nextSrkHandle + 1;
      }
    }
  }

  // although the TPM will never be able to load objects at all possible
  // persistent storage handles, this check that we didn't find all handles
  // in use is for completeness (i.e., this check should probably never fail)
  if (*nextSrkHandle >= TPM2_PLATFORM_PERSISTENT)
  {
    kmyth_log(LOG_ERR, "no available persistent storage handles");
    return 1;
  }
  kmyth_log(LOG_DEBUG, "next available persistent storage handle at 0x%08X",
            *nextSrkHandle);

  // if SRK must be re-derived, check valid next handle was also supplied
  if ((*srkHandle == 0) && (*nextSrkHandle == 0))
  {
    kmyth_log(LOG_ERR, "SRK must be re-derived, but TPM cannot support %s"
              "loading additional persistent objects ... exiting");
    return 1;
  }

  return 0;
}

//############################################################################
// check_if_srk()
//############################################################################
int check_if_srk(TSS2_SYS_CONTEXT * sapi_ctx, TPM2_HANDLE handle, bool *isSRK)
{
  // initialize 'isSRK' result to false - early termination should not result
  // in a true value passed back (even if the return code indicates an error)
  *isSRK = false;

  kmyth_log(LOG_DEBUG, "checking handle %08X", handle);

  // Read the public info of the object referenced by the handle
  //
  // Note: Although Tss2_Sys_ReadPublic() takes command and response
  //       authorization structures as parameters, the TPM specification
  //       indicates that this command does not require authorization.
  //       Therefore, we provide NULL values when invoking this function.
  TPM2B_PUBLIC publicOut;
  TPM2B_NAME nameOut;
  TPM2B_NAME qualNameOut;

  publicOut.size = 0;
  nameOut.size = 0;
  qualNameOut.size = 0;
  TSS2L_SYS_AUTH_COMMAND *nullCmdAuths = NULL;
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL;
  TPM2_RC rc = Tss2_Sys_ReadPublic(sapi_ctx,
                                   handle,
                                   nullCmdAuths,
                                   &publicOut,
                                   &nameOut,
                                   &qualNameOut,
                                   nullRspAuths);

  if (rc != TPM2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_ReadPublic(): TPM rc = 0x%08X", rc);
    return 1;
  }

  // use a boolean to persist any failed SRK check result
  bool failed_SRK_check = false;

  // First check that hash algorithm is correct. 
  if (publicOut.publicArea.nameAlg != KMYTH_HASH_ALG)
  {
    // persistent key has the wrong hash algorithm. 
    failed_SRK_check = true;
    kmyth_log(LOG_DEBUG, "wrong hash algorithm (ALG_ID=0x%08X)",
              publicOut.publicArea.nameAlg);
  }

  // And similarly that the public key algorithm is correct. 
  if (publicOut.publicArea.type != KMYTH_KEY_PUBKEY_ALG)
  {
    // persistent key has the wrong public key algorithm 
    failed_SRK_check = true;
    kmyth_log(LOG_DEBUG, "wrong public key algorithm (ALG_ID=0x%08X)",
              publicOut.publicArea.type);
  }

  // check that the attribute bit array for object has necessary options set
  // fixed tpm bit (1) - hierarchy of the object may not change
  TPMA_OBJECT objAttr = publicOut.publicArea.objectAttributes;

  // fixedTPM (bit 1) - should be set - SRK is a primary key that cannot be
  //                    duplicated for use on a different TPM
  if (!(objAttr & TPMA_OBJECT_FIXEDTPM))
  {
    failed_SRK_check = true;
    kmyth_log(LOG_DEBUG, "fixedTPM clear, should be set");
  }

  // fixedParent (bit 4) - should be set - SRK's parent may not be changed
  if (!(objAttr & TPMA_OBJECT_FIXEDPARENT))
  {
    failed_SRK_check = true;
    kmyth_log(LOG_DEBUG, "fixedParent clear, should be set");
  }

  // sensitiveDataOrigin (bit 5) - should be set - SRK should be generated
  //                               (derived from primary seed) by TPM
  if (!(objAttr & TPMA_OBJECT_SENSITIVEDATAORIGIN))
  {
    failed_SRK_check = true;
    kmyth_log(LOG_DEBUG, "sensitiveDataOrigin clear, should be set");
  }

  // noDA (bit 10) - should be clear - SRK authorization failures for the SRK
  //                 should trigger the dictionary attack protection logic and
  //                 authorization of the SRK should be blocked if the TPM is
  //                 in lockout
  if (objAttr & TPMA_OBJECT_NODA)
  {
    failed_SRK_check = true;
    kmyth_log(LOG_DEBUG, "noDA set, should be clear");
  }

  // restricted (bit 16) - must be set - SRK is a parent key
  if (!(objAttr & TPMA_OBJECT_RESTRICTED))
  {
    failed_SRK_check = true;
    kmyth_log(LOG_DEBUG, "restricted bit clear, should be set");
  }

  // decrypt (17) - must be set - SRK must be used to decrypt SKs 
  if (!(objAttr & TPMA_OBJECT_DECRYPT))
  {
    failed_SRK_check = true;
    kmyth_log(LOG_DEBUG, "decrypt bit clear, should be set");
  }

  // Next, validate the object name value 
  // NOTE: According to the spec, the qualified Name is the hash of the
  //       previous names prepended onto the current name. 
  // The only parent/ancestor of the storage root key is the storage seed. 
  // The TPM2_RH_OWNER handle (0x40000001) references the Storage Primary
  // Seed (SPS), the ownerAuth, and the ownerPolicy
  int name_buf_len = nameOut.size + sizeof(TPM2_HANDLE);
  unsigned char name_buf[name_buf_len];
  TPM2_HANDLE srk_parent_handle = htonl(TPM2_RH_OWNER);

  memcpy(name_buf, &srk_parent_handle, sizeof(TPM2_HANDLE));
  memcpy(name_buf + sizeof(TPM2_HANDLE), nameOut.name, nameOut.size);
  kmyth_log(LOG_DEBUG, "name: 0x%02X .. %02X", name_buf[0],
            name_buf[name_buf_len - 1]);

  // Hash name and verify that it matches qualified name
  int qname_buf_len = KMYTH_DIGEST_SIZE + sizeof(TPM2_ALG_ID);
  unsigned char qname_buf[qname_buf_len];
  TPM2_ALG_ID qname_algID = htons(KMYTH_HASH_ALG);

  memcpy(qname_buf, &qname_algID, sizeof(TPM2_ALG_ID));
  EVP_Digest(name_buf, name_buf_len, qname_buf + sizeof(TPM2_ALG_ID), NULL,
             KMYTH_OPENSSL_HASH, NULL);
  kmyth_log(LOG_DEBUG, "hashed name: 0x%02X..%02X", qname_buf[0],
            qname_buf[qname_buf_len - 1]);
  kmyth_log(LOG_DEBUG, "qualified name: 0x%02X..%02X",
            qualNameOut.name[0], qualNameOut.name[qualNameOut.size - 1]);
  bool srkNameMatch = true;

  if (qname_buf_len != qualNameOut.size)
  {
    srkNameMatch = false;
  }
  else
  {
    for (int i = 0; i < qualNameOut.size; i++)
    {
      if (qualNameOut.name[i] != qname_buf[i])
      {
        srkNameMatch = false;
      }
    }
  }
  if (!srkNameMatch)
  {
    failed_SRK_check = true;
    kmyth_log(LOG_DEBUG, "hashed name mismatches SRK qualified name");
  }

  // end of checks, set isSRK flag parameter appropriately
  *isSRK = !failed_SRK_check;

  kmyth_log(LOG_DEBUG, "handle 0x%08X: isSRK = %s", handle,
            (*isSRK ? "true" : "false"));

  return 0;
}

//############################################################################
// put_srk_into_persistent_storage()
//############################################################################
int put_srk_into_persistent_storage(TSS2_SYS_CONTEXT * sapi_ctx,
                                    TPM2_HANDLE srkHandle, TPM2B_AUTH sps_auth)
{
  kmyth_log(LOG_DEBUG, "deriving SRK ..");

  // Check that the handle passed in is within persistent range
  if ((srkHandle < TPM2_PERSISTENT_FIRST) || (srkHandle > TPM2_PERSISTENT_LAST))
  {
    kmyth_log(LOG_ERR,
              "SRK handle (0x%08X) out of persistent range ... exiting",
              srkHandle);
    return 1;
  }

  // Create and set up sensitive data input for re-derived storage root key
  // object:
  //   - The Storage (Owner) Hierarchy password (emptyAuth by default) is
  //     needed to authorize use of the Storage Primary Seed (SPS). We give the
  //     SRK object derived from the SPS the same authorization requirements
  //     as the SPS (password authorization - need to know Owner Hierarchy
  //     authorization string).
  //   - For a key object, we specify the data size as zero to leave the data
  //     buffer empty.
  TPM2B_SENSITIVE_CREATE srk_sensitive;
  uint8_t *object_data = NULL;
  size_t object_data_size = 0;

  srk_sensitive.sensitive.data.size = 0;
  srk_sensitive.sensitive.userAuth.size = 0;

  if (init_kmyth_object_sensitive(sps_auth,
                                  object_data,
                                  object_data_size, &srk_sensitive))
  {
    kmyth_log(LOG_ERR, "error initializing sensitive data ... exiting");
    return 1;
  }

  // Create and setup public data "template" for the SRK
  TPM2B_PUBLIC srk_template;
  TPM2B_DIGEST empty_policy_digest;

  srk_template.size = 0;
  empty_policy_digest.size = 0;
  if (init_kmyth_object_template(true,
                                 empty_policy_digest,
                                 &(srk_template.publicArea)))
  {
    kmyth_log(LOG_ERR, "create SRK template error ... exiting");
    return 1;
  }

  // Create the SRK primary object (derived from Storage Primary Seed) using
  // the input parameters just setup.
  SESSION *nullSession = NULL;  // SRK does not use policy auth
  TPM2B_PRIVATE *nullPrivateBlob = NULL;  // TPM derives SRK, not exported
  TPM2B_PUBLIC *nullPublicBlob = NULL;
  TPML_PCR_SELECTION emptyPCRList;  // no PCR auth (SRK or SPS)

  emptyPCRList.count = 0;
  if (create_kmyth_object(sapi_ctx,
                          nullSession,
                          TPM2_RH_OWNER,
                          sps_auth,
                          emptyPCRList,
                          srk_sensitive,
                          srk_template,
                          emptyPCRList,
                          srkHandle, nullPrivateBlob, nullPublicBlob))
  {
    kmyth_log(LOG_ERR, "error deriving SRK ... exiting");
    return 1;
  }

  return 0;
}

//############################################################################
// create_and_load_sk()
//############################################################################
int create_and_load_sk(TSS2_SYS_CONTEXT * sapi_ctx,
                       TPM2_HANDLE srk_handle,
                       TPM2B_AUTH srk_authVal,
                       TPM2B_AUTH sk_authVal,
                       TPML_PCR_SELECTION sk_pcrList,
                       TPM2B_DIGEST sk_authPolicy,
                       TPM2_HANDLE * sk_handle,
                       TPM2B_PRIVATE * sk_private, TPM2B_PUBLIC * sk_public)
{
  // Create and set up sensitive data input for new storage key object:
  //   - The authVal (hash of user specified authorization string or default
  //     all-zero hash) is passed into this function by the caller
  //   - For a key object, we specify the data as NULL to leave the data buffer
  //     empty (zero-size). When the key (SK in this case) is created, the TPM
  //     will populate the buffer with the key and set size to the key length.
  TPM2B_SENSITIVE_CREATE sk_sensitive;
  uint8_t *skd = NULL;
  size_t skd_size = 0;

  sk_sensitive.sensitive.data.size = 0;
  sk_sensitive.sensitive.userAuth.size = 0;
  if (init_kmyth_object_sensitive(sk_authVal, skd, skd_size, &sk_sensitive))
  {
    kmyth_log(LOG_ERR, "error initializing sensitive data ... exiting");
    return 1;
  }

  // Create empty and then set up public data "template" for storage key
  TPM2B_PUBLIC sk_template;

  sk_template.size = 0;
  if (init_kmyth_object_template(true,
                                 sk_authPolicy, &(sk_template.publicArea)))
  {
    kmyth_log(LOG_ERR, "SK create template error ... exiting");
    return 1;
  }

  // Create new storage key
  SESSION *nullSession = NULL;  // SRK (parent) auth is not policy based
  TPM2_HANDLE unusedHandle = 0; // creating SK, not loading
  TPML_PCR_SELECTION emptyPCRList;  // SRK (parent) has no PCR-based auth

  emptyPCRList.count = 0;       // no auth policy session means no PCR criteria

  if (create_kmyth_object(sapi_ctx,
                          nullSession,
                          srk_handle,
                          srk_authVal,
                          emptyPCRList,
                          sk_sensitive,
                          sk_template,
                          sk_pcrList, unusedHandle, sk_private, sk_public))
  {
    kmyth_log(LOG_ERR, "error creating storage key ... exiting");
    return 1;
  }

  // As this newly created storage key will be used by the TPM, we must load it
  if (load_kmyth_object(sapi_ctx,
                        nullSession,
                        srk_handle,
                        srk_authVal,
                        emptyPCRList, sk_private, sk_public, sk_handle))
  {
    kmyth_log(LOG_ERR, "failed to load storage key ... exiting");
    return 1;
  }

  kmyth_log(LOG_DEBUG, "storage key object created and loaded");
  return 0;
}
