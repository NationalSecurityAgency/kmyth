/**
 * @file  object_tools.h
 *
 * @brief Provides TPM 2.0 utility functions for identifying, creating,
 *        loading, managing, and otherwise interacting with TPM2 objects
 *        required by Kmyth
 */

#ifndef OBJECT_TOOLS_H
#define OBJECT_TOOLS_H

#include <stdbool.h>

#include "tpm2_interface.h"

/**
 * @brief Fill in sensitive data input used for Kmyth object creation.
 *
 * @param[in]  object_auth     Authorization value to be applied to
 *                             authorization policy for Kmyth object
 *
 * @param[in]  object_data     Data to be sealed:
 *                             <UL>
 *                               <LI> if a key object, leave null and the TPM
 *                                    will populate with the key value
 *                               </LI>
 *                               <LI> if a sealed data object, this is the data
 *                                    to be sealed
 *                               </LI>
 *                             </UL>
 *
 * @param[in]  object_dataSize Size of data to be sealed:
 *                             <UL>
 *                               <LI> if a key object, set to zero and the TPM
 *                                    will replace with the key length
 *                               </LI>
 *                               <LI> if a sealed data object, must specify
 *                                    the size of value in data buffer
 *                               </LI>
 *                             </UL>
 *
 * @param[out] sensitiveArea:  TPM2B_SENSITIVE_CREATE structure used in the
 *                             creation of a Kmyth object - passed as a
 *                             pointer to this struct
 *
 * @return 0 if success, 1 if error.
 */
int init_kmyth_object_sensitive(TPM2B_AUTH object_auth,
                                uint8_t * object_data,
                                size_t object_dataSize,
                                TPM2B_SENSITIVE_CREATE * sensitiveArea);

/**
 * @brief Fill in public template used to create Kmyth object.
 *
 * Example parameters initialized include:
 * <UL>
 *   <LI> attributes </LI>
 *   <LI> algorithm options </LI>
 * </UL>
 *
 * @param[in]  isKey       Boolean flag indicating whether or not
 *                         object is a key:
 *                         <UL>
 *                           <LI> true = object is a key </LI>
 *                           <LI> false = object is a blob </LI>
 *                         </UL>
 * 
 * @param[in]  auth_policy Authorization policy digest for object -
 *                         passed as a pointer to this buffer
 *
 * @param[out] pubArea:    Public template (TPMT_PUBLIC) to be initialized -
 *                         passed as a pointer to this structure
 *
 * @return 0 if success, 1 if error. 
 */
int init_kmyth_object_template(bool isKey, TPM2B_DIGEST auth_policy,
                               TPMT_PUBLIC * pubArea);

/**
 * @brief Set attributes for Kmyth objects (SRK, SK, or sealed data).
 * 
 * These attributes indicate an object’s use, its authorization types, and
 * its relationship to other objects. TPM object attributes are in five
 * classes: usage, authorization, duplication, creation, and persistence.
 * The state of the attributes is determined when the object is created
 * and they are never changed by the TPM.
 *
 * @param[in]  isKey        Boolean flag indicating whether or not
 *                          object is a key:
 *                          <UL>
 *                            <LI> true = object is a key </LI>
 *                            <LI> false = object is a blob </LI>
 *                          </UL>
 * 
 * @param[out] objectAttrib Object attributes struct (TPMA_OBJECT) to
 *                          be configured - passed as a pointer to this buffer
 *
 * @return 0 if success, 1 if error.
 */
int init_kmyth_object_attributes(bool isKey, TPMA_OBJECT * objectAttrib);

/**
 * @brief Set parameters for Kmyth objects (SRK, SK, or sealed data).
 * 
 * The parameters of an object are dependent on the object type and describe
 * details of the object.
 * <UL>
 *   <LI> Asymmetric (RSA or ECC) key object parameters specify the associated
 *        key size, signing scheme, and symmetric encryption methods.
 *   </LI>
 *   <LI> Symmetric key object parameters specify the size of the key and the
 *        default encryption mode.
 *   </LI>
 *   <LI> Keyed hash (sealed data or HMAC key) object parameters specify the
 *        hash scheme and hash/key derivation function algorithm.
 *   </LI>
 * </UL>
 *
 * For a storage key that has the fixedParent attribute set, these parameters
 * will be identical to those of its parent. Kmyth objects are currently
 * configured for no duplication, so fixedParent is set and this applies.
 *
 * @param[in]  objectType   The type of TPM object with the following possible
 *                          values:
 *                          <UL>
 *                            <LI> TPM_ALG_RSA </LI>
 *                            <LI> TPM_ALG_ECC </LI>
 *                            <LI> TPM_ALG_SYMCIPHER </LI>
 *                            <LI> TPM_ALG_KEYEDHASH </LI>
 *                          </UL>
 * 
 * @param[out] objectParams Type-specific object parameters struct
 *                          (TPMU_PUBLIC_PARMS) to be configured -
 *                          passed as a pointer to this buffer.
 *
 * @return None
 */
int init_kmyth_object_parameters(TPMI_ALG_PUBLIC objectType,
                                 TPMU_PUBLIC_PARMS * objectParams);

/**
 * @brief Set unique identifier for Kmyth objects (SRK, SK, or sealed data).
 * 
 * An object's item-specific information (its unique field) is the only part of
 * the public template that will be replaced by the TPM in the creation
 * process. Any value may be placed in this field as long as the structure of
 * the value is consistent with the type field. If the size of this field is
 * set to zero, the TPM will replace it with a correctly sized structure.
 *
 * Computation of this unique value uses one or more values contained in the
 * sensitive area for the object. For asymmetric objects, the public key,
 * which is mathematically linked to the private key is put in this buffer.
 * For symmetric objects (symmetric keys, HMAC keys, and data blobs), the key
 * (or data) is hashed with a TPM-generated obfuscation value and the resulting
 * digest is placed in this buffer as the unique value.
 *
 * @param[in]  objectType   The type of TPM object with the following possible
 *                          values:
 *                          <UL>
 *                            <LI> TPM_ALG_RSA </LI>
 *                            <LI> TPM_ALG_ECC </LI>
 *                            <LI> TPM_ALG_SYMCIPHER </LI>
 *                            <LI> TPM_ALG_KEYEDHASH </LI>
 *                          </UL>
 * 
 * @param[out] objectUnique Type-specific object unique struct (TPMU_PUBLIC_ID)
 *                          to be configured - passed as a pointer to buffer
 *
 * @return None
 */
int init_kmyth_object_unique(TPMI_ALG_PUBLIC objectType,
                             TPMU_PUBLIC_ID * objectUnique);

/**
 * @brief Create a new TPM 2.0 object (e.g., key or blob).
 *
 * @param[in]  sapi_ctx                System API (SAPI) context, must be
 *                                     initialized and passed in as pointer
 *                                     to the SAPI context
 *
 * @param[in]  createObjectAuthSession Session used to authorize TPM commands
 *                                     needed to create a new TPM 2.0 object:
 *                                     <UL>
 *                                       <LI> If creating either an SRK or an
 *                                            SK, this value is null, as
 *                                            password authorization is
 *                                            employed to authorize use of
 *                                            the parent (storage primary seed
 *                                            for SRK and SRK for SK) to
 *                                            create this key object
 *                                       </LI>
 *                                       <LI> If creating a 'data' blob, this
 *                                            value is the handle for the
 *                                            TPM 2.0 policy session setup to
 *                                            authorize use of the SK to create
 *                                            the sealed 'data' blob object
 *                                       </LI>
 *                                     </UL>
 *
 * @param[in]  parent_handle           TPM 2.0 handle value that references
 *                                     the parent, in the hierarchy, that this
 *                                     new object is to be created under:
 *                                     <UL>
 *                                       <LI> If creating an SRK, this value
 *                                            is TPM2_RH_OWNER
 *                                       </LI>
 *                                       <LI> If creating a SK, this value
 *                                            is the handle for the SRK
 *                                       </LI>
 *                                       <LI> If creating a 'data' blob object,
 *                                            this value is the SK handle
 *                                       </LI>
 *                                     </UL> 
 *
  * @param[in]  parent_auth             Creation of a new object requires the
 *                                     authorization criteria of the parent
 *                                     object it is to be created under:
 *                                     <UL>
 *                                       <LI> If creating either an SRK or an
 *                                            SK, this value must contain the
 *                                            owner/storage hierarchy password 
 *                                            (emptyAuth by default)
 *                                       </LI>
 *                                       <LI> If creating a 'data' blob, the SK
 *                                            parent object's authorization
 *                                            policy requires an authVal
 *                                            <UL>
 *                                              <LI> all-zero hash (hash of
 *                                                   default emptyAuth)
 *                                              </LI>
 *                                              <LI> hash of the supplied
 *                                                   authorization bytes,
 *                                                   if applicable
 *                                              </LI>
 *                                            </UL>
 *                                       </LI>
 *                                     </UL>
 *
 * @param[in]  parent_pcrList          Creation of a new object requires the
 *                                     authorization criteria of the parent
 *                                     object it is to be created under:
 *                                     <UL>
 *                                       <LI> If creating either an SRK or an
 *                                            SK, this value must contain an
 *                                            empty PCR selection list
 *                                       </LI>
 *                                       <LI> If creating a 'data' blob, the SK
 *                                            parent object's authorization
 *                                            policy requires the PCR Select
 *                                            structure indicating the PCR
 *                                            values that must match
 *                                       </LI>
 *                                     </UL>
 *
 *
 * @param[in]  object_sensitive        Initialized TPM2B_SENSITIVE_CREATE
 *                                     structure containing:
 *                                     <UL>
 *                                       <LI> authVal for created object </LI>
 *                                       <LI> data to be sealed </LI>
 *                                         <UL>
 *                                           <LI> NULL for key objects </LI>
 *                                           <LI> data of non-zero length for
 *                                                sealed data objects
 *                                           </LI>
 *                                         </UL>
 *                                     </UL>
 *
 * @param[in]  object_template         Initialized TPM 2.0 object template
 *                                     (public meta-data) used for creating
 *                                     the object, specifying:
 *                                     <UL>
 *                                       <LI> public algorithm (type) </LI>
 *                                       <LI> hash algorithm </LI>
 *                                       <LI> object attributes </LI>
 *                                       <LI> authorization policy digest </LI>
 *                                       <LI> algorithm specific params </LI>
 *                                       <LI> unique value </LI>
 *                                     </UL>
 *
 * @param[in]  object_pcrSelect        Initialized PCR Selection structure to
 *                                     be employed by authorization policy for
 *                                     created object:
 *                                     <UL>
 *                                       <LI> If creating SRK, empty PCR
 *                                            Selection struct - password
 *                                            authorization is used.
 *                                       </LI>
 *                                       <LI> If creating SK or data object,
 *                                            PCR Selection struct
 *                                            corresponding to user specified
 *                                            PCR values.
 *                                       </LI>
 *                                     </UL>  
 *
 * @param[out] object_dest_handle      TPM2_HANDLE value used to return the
 *                                     handle for the object created by this
 *                                     function. As zero is an invalid handle
 *                                     value, recommend passing in a handle
 *                                     value initialized to zero. A valid
 *                                     handle must then have been sourced by
 *                                     this function.
 *
 * @param[out] object_private          Encrypted TPM 2.0 "private blob" for created
 *                                     object - passed as a pointer to the
 *                                     TPM2B_PRIVATE sized buffer containing the
 *                                     object's encrypted private area contents
 *
 * @param[out] object_public           TPM 2.0 "public blob" for created object -
 *                                     passed as a pointer to the TPM2B_PUBLIC
 *                                     sized buffer containing the
 *                                     object's public area contents
 *
 * @return 0 if success, 1 if error. 
 */
int create_kmyth_object(TSS2_SYS_CONTEXT * sapi_ctx,
                        SESSION * createObjectAuthSession,
                        TPM2_HANDLE parent_handle,
                        TPM2B_AUTH parent_auth,
                        TPML_PCR_SELECTION parent_pcrList,
                        TPM2B_SENSITIVE_CREATE object_sensitive,
                        TPM2B_PUBLIC object_template,
                        TPML_PCR_SELECTION object_pcrSelect,
                        TPM2_HANDLE object_dest_handle,
                        TPM2B_PRIVATE * object_private,
                        TPM2B_PUBLIC * object_public);

/**
 * @brief Loads an object (e.g., key) into the TPM 2.0.
 *
 * @param[in]  sapi_ctx              System API (SAPI) context, must be
 *                                   initialized and passed in as pointer
 *                                   to the SAPI context.
 *
 * @param[in]  loadObjectAuthSession Session used to authorize TPM commands
 *                                   needed to load a TPM 2.0 object:
 *                                   <UL>
 *                                     <LI> If loading either an SRK or an
 *                                          SK, this value is null, as
 *                                          password authorization is
 *                                          employed to authorize loading the
 *                                          object under the parent (storage
 *                                          primary seed for SRK and SRK for
 *                                          SK)
 *                                     </LI>
 *                                     <LI> If loading a 'data' blob, this
 *                                          value is the handle for the
 *                                          TPM 2.0 policy session setup to
 *                                          authorize loading under SK
 *                                     </LI>
 *                                   </UL>
 *
 * @param[in]  parent_handle         TPM 2.0 handle value that references
 *                                   parent, in the hierarchy, of the object
 *                                   to be loaded. As the object is loaded
 *                                   under the parent in the hierarchy, the
 *                                   "load" command requires that the
 *                                   authorization criteria of the parent
 *                                   be satisfied by the caller.
 * 
 * @param[in]  parent_auth           Authorization value for the parent (SRK
 *                                   if a SK is being loaded or SK if a data
 *                                   object is being loaded). In the case that
 *                                   the parent is an SRK, this should
 *                                   respresent the password for the owner
 *                                   (storage) hierarchy. Alternatively,
 *                                   if the parent is an SK, this should be
 *                                   the hash of the authorization bytes,
 *                                   which are empty (all-zero hash) by default.
 *
 * @param[in]  parent_pcrList        PCR List structure indicating the PCR
 *                                   values that the parent (SRK if a SK is
 *                                   being loaded or SK if a data object is
 *                                   being loaded) was sealed to.
 *
 * @param[in]  in_private            Encrypted TPM 2.0 "private blob" for
 *                                   object to be loaded - passed as a pointer
 *                                   to the TPM2B_PRIVATE sized buffer
 *                                   containing the object's encrypted private
 *                                   area contents
 *
 * @param[in]  in_public             TPM 2.0 "public blob" for object to be
 *                                   loaded - passed as a pointer to the
 *                                   TPM2B_PUBLIC sized buffer containing the
 *                                   object's public area contents
 *
 * @param[out] object_handle         TPM 2.0 handle value for the loaded
 *                                   object - passed as a pointer to the
 *                                   handle value.
 *
 * @return 0 if success, 1 if error. 
 */
int load_kmyth_object(TSS2_SYS_CONTEXT * sapi_ctx,
                      SESSION * loadObjectAuthSession,
                      TPM2_HANDLE parent_handle,
                      TPM2B_AUTH parent_auth,
                      TPML_PCR_SELECTION parent_pcrList,
                      TPM2B_PRIVATE * in_private,
                      TPM2B_PUBLIC * in_public, TPM2_HANDLE * object_handle);

/**
 * @brief Unseals a Kmyth TPM data object 
 *
 * @param[in]  sapi_ctx                   System API (SAPI) context, must be
 *                                        initialized and passed in as pointer
 *                                        to the SAPI context.
 *
 * @param[in/out] unsealObjectAuthSession Handle of the TPM 2.0 session used to
 *                                        authorize the commands required to
 *                                        unseal the data object.
 *
 * @param[in]  object_handle              Handle of the TPM 2.0 data object to
 *                                        be unsealed.
 *
 * @param[in]  object_auth                Authorization value associated with
 *                                        the data object when it was created
 *                                        and now needed to unseal it. Should
 *                                        be hash of the authorization bytes or
 *                                        the default all-zero hash associated
 *                                        with empty authorization bytes.
 *
 * @param[in]  object_pcrList             PCR List structure indicating the PCR
 *                                        values to which the data object was
 *                                        sealed.
 *
 * @param[out] object_sensitive           The unsealed (unencrypted) result.
 *
 * @return 0 if success, 1 if error. 
 */
int unseal_kmyth_object(TSS2_SYS_CONTEXT * sapi_ctx,
                        SESSION * unsealObjectAuthSession,
                        TPM2_HANDLE object_handle,
                        TPM2B_AUTH object_auth,
                        TPML_PCR_SELECTION object_pcrList,
                        TPM2B_SENSITIVE_DATA * object_sensitive);

#endif /* OBJECT_TOOLS_H */
