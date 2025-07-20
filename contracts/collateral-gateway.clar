;; Collateral Gateway: Secure Document Management and Access Control
;; This contract provides a robust infrastructure for managing business documents with granular access control,
;; ensuring secure storage, permission management, and comprehensive audit logging on the Stacks blockchain.

;; Error Codes
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-BUSINESS-DUPLICATE (err u101))
(define-constant ERR-BUSINESS-NOT-FOUND (err u102))
(define-constant ERR-DOCUMENT-DUPLICATE (err u103))
(define-constant ERR-DOCUMENT-NOT-FOUND (err u104))
(define-constant ERR-USER-NOT-FOUND (err u105))
(define-constant ERR-INVALID-PERMISSION (err u106))
(define-constant ERR-ACCESS-DENIED (err u107))
(define-constant ERR-INVALID-ACTION (err u108))

;; Permission Levels
(define-constant PERMISSION-NONE u0)
(define-constant PERMISSION-READ u1)
(define-constant PERMISSION-MODIFY u2)
(define-constant PERMISSION-MANAGE u3)
(define-constant PERMISSION-FULL u4)

;; Action Types for Audit Trail
(define-constant ACTION-REGISTER u1)
(define-constant ACTION-CREATE u2)
(define-constant ACTION-UPDATE u3)
(define-constant ACTION-SHARE u4)
(define-constant ACTION-ACCESS u5)

;; Data Maps for Business and Document Management

;; Business Registry
(define-map enterprise-registry
  { enterprise-id: (string-ascii 64) }
  { 
    owner: principal,
    name: (string-ascii 256),
    registered-at: uint,
    active: bool
  }
)

;; Document Metadata Storage
(define-map document-vault
  { enterprise-id: (string-ascii 64), document-id: (string-ascii 64) }
  {
    name: (string-ascii 256),
    description: (string-utf8 500),
    document-hash: (buff 32),
    document-type: (string-ascii 64),
    created-at: uint,
    last-updated: uint,
    version: uint,
    active: bool
  }
)

;; Document Access Permissions
(define-map document-access-control
  { enterprise-id: (string-ascii 64), document-id: (string-ascii 64), user: principal }
  {
    permission-level: uint,
    granted-by: principal,
    granted-at: uint
  }
)

;; Comprehensive Audit Logging
(define-map document-audit-trail
  { enterprise-id: (string-ascii 64), document-id: (string-ascii 64), log-id: uint }
  {
    user: principal,
    action: uint,
    timestamp: uint,
    details: (string-utf8 500)
  }
)

;; Audit Log Sequence Tracking
(define-map audit-sequence-tracker
  { enterprise-id: (string-ascii 64), document-id: (string-ascii 64) }
  { next-log-id: uint }
)

;; Private Helper Functions

;; Generate Next Audit Log Sequence
(define-private (get-next-audit-log-id (enterprise-id (string-ascii 64)) (document-id (string-ascii 64)))
  (let ((current-counter (default-to { next-log-id: u1 } (map-get? audit-sequence-tracker { enterprise-id: enterprise-id, document-id: document-id }))))
    (begin
      (map-set audit-sequence-tracker 
        { enterprise-id: enterprise-id, document-id: document-id }
        { next-log-id: (+ (get next-log-id current-counter) u1) }
      )
      (get next-log-id current-counter)
    )
  )
)

;; Record Audit Event
(define-private (log-audit-event
  (enterprise-id (string-ascii 64))
  (document-id (string-ascii 64))
  (user principal)
  (action uint)
  (details (string-utf8 500))
)
  (let ((log-id (get-next-audit-log-id enterprise-id document-id)))
    (map-set document-audit-trail
      { enterprise-id: enterprise-id, document-id: document-id, log-id: log-id }
      {
        user: user,
        action: action,
        timestamp: block-height,
        details: details
      }
    )
    true
  )
)

;; Validate Permission Level
(define-private (has-permission
  (enterprise-id (string-ascii 64))
  (document-id (string-ascii 64))
  (user principal)
  (required-permission uint)
)
  (let (
    (enterprise-data (map-get? enterprise-registry { enterprise-id: enterprise-id }))
    (permission-data (map-get? document-access-control { enterprise-id: enterprise-id, document-id: document-id, user: user }))
  )
    (if (is-none enterprise-data)
      false
      (if (is-eq (get owner (unwrap-panic enterprise-data)) user)
        true
        (if (is-none permission-data)
          false
          (>= (get permission-level (unwrap-panic permission-data)) required-permission)
        )
      )
    )
  )
)

;; Validate Document Existence
(define-private (document-exists (enterprise-id (string-ascii 64)) (document-id (string-ascii 64)))
  (is-some (map-get? document-vault { enterprise-id: enterprise-id, document-id: document-id }))
)

;; Public Functions

;; Register New Enterprise
(define-public (register-enterprise (enterprise-id (string-ascii 64)) (name (string-ascii 256)))
  (let ((existing-enterprise (map-get? enterprise-registry { enterprise-id: enterprise-id })))
    (if (is-some existing-enterprise)
      ERR-BUSINESS-DUPLICATE
      (begin
        (map-set enterprise-registry
          { enterprise-id: enterprise-id }
          {
            owner: tx-sender,
            name: name,
            registered-at: block-height,
            active: true
          }
        )
        (log-audit-event enterprise-id "" tx-sender ACTION-REGISTER u"Enterprise registered")
        (ok true)
      )
    )
  )
)

;; Add New Document
(define-public (add-document
  (enterprise-id (string-ascii 64))
  (document-id (string-ascii 64))
  (name (string-ascii 256))
  (description (string-utf8 500))
  (document-hash (buff 32))
  (document-type (string-ascii 64))
)
  (let ((enterprise-data (map-get? enterprise-registry { enterprise-id: enterprise-id })))
    (if (is-none enterprise-data)
      ERR-BUSINESS-NOT-FOUND
      (if (not (is-eq (get owner (unwrap-panic enterprise-data)) tx-sender))
        ERR-UNAUTHORIZED
        (if (document-exists enterprise-id document-id)
          ERR-DOCUMENT-DUPLICATE
          (begin
            (map-set document-vault
              { enterprise-id: enterprise-id, document-id: document-id }
              {
                name: name,
                description: description,
                document-hash: document-hash,
                document-type: document-type,
                created-at: block-height,
                last-updated: block-height,
                version: u1,
                active: true
              }
            )
            (map-set document-access-control
              { enterprise-id: enterprise-id, document-id: document-id, user: tx-sender }
              {
                permission-level: PERMISSION-FULL,
                granted-by: tx-sender,
                granted-at: block-height
              }
            )
            (log-audit-event enterprise-id document-id tx-sender ACTION-CREATE u"Document added")
            (ok true)
          )
        )
      )
    )
  )
)

;; Update Existing Document
(define-public (update-document
  (enterprise-id (string-ascii 64))
  (document-id (string-ascii 64))
  (name (string-ascii 256))
  (description (string-utf8 500))
  (document-hash (buff 32))
  (document-type (string-ascii 64))
)
  (let (
    (document-data (map-get? document-vault { enterprise-id: enterprise-id, document-id: document-id }))
  )
    (if (is-none document-data)
      ERR-DOCUMENT-NOT-FOUND
      (if (not (has-permission enterprise-id document-id tx-sender PERMISSION-MODIFY))
        ERR-UNAUTHORIZED
        (begin
          (map-set document-vault
            { enterprise-id: enterprise-id, document-id: document-id }
            {
              name: name,
              description: description,
              document-hash: document-hash,
              document-type: document-type,
              created-at: (get created-at (unwrap-panic document-data)),
              last-updated: block-height,
              version: (+ (get version (unwrap-panic document-data)) u1),
              active: true
            }
          )
          (log-audit-event enterprise-id document-id tx-sender ACTION-UPDATE u"Document updated")
          (ok true)
        )
      )
    )
  )
)

;; Grant Document Access
(define-public (grant-document-access
  (enterprise-id (string-ascii 64))
  (document-id (string-ascii 64))
  (user principal)
  (permission-level uint)
)
  (if (not (has-permission enterprise-id document-id tx-sender PERMISSION-MANAGE))
    ERR-UNAUTHORIZED
    (if (not (document-exists enterprise-id document-id))
      ERR-DOCUMENT-NOT-FOUND
      (if (or (< permission-level PERMISSION-READ) (> permission-level PERMISSION-FULL))
        ERR-INVALID-PERMISSION
        (begin
          (map-set document-access-control
            { enterprise-id: enterprise-id, document-id: document-id, user: user }
            {
              permission-level: permission-level,
              granted-by: tx-sender,
              granted-at: block-height
            }
          )
          (log-audit-event 
            enterprise-id 
            document-id 
            tx-sender 
            ACTION-SHARE 
            u"Document access granted"
          )
          (ok true)
        )
      )
    )
  )
)

;; Revoke Document Access
(define-public (revoke-document-access
  (enterprise-id (string-ascii 64))
  (document-id (string-ascii 64))
  (user principal)
)
  (if (not (has-permission enterprise-id document-id tx-sender PERMISSION-MANAGE))
    ERR-UNAUTHORIZED
    (if (not (document-exists enterprise-id document-id))
      ERR-DOCUMENT-NOT-FOUND
      (begin
        (map-delete document-access-control { enterprise-id: enterprise-id, document-id: document-id, user: user })
        (log-audit-event 
          enterprise-id 
          document-id 
          tx-sender 
          ACTION-SHARE 
          u"Document access revoked"
        )
        (ok true)
      )
    )
  )
)

;; Access Document
(define-public (access-document
  (enterprise-id (string-ascii 64))
  (document-id (string-ascii 64))
)
  (if (not (has-permission enterprise-id document-id tx-sender PERMISSION-READ))
    ERR-ACCESS-DENIED
    (if (not (document-exists enterprise-id document-id))
      ERR-DOCUMENT-NOT-FOUND
      (begin
        (log-audit-event enterprise-id document-id tx-sender ACTION-ACCESS u"Document accessed")
        (ok true)
      )
    )
  )
)

;; Delete Document (Soft Delete)
(define-public (delete-document
  (enterprise-id (string-ascii 64))
  (document-id (string-ascii 64))
)
  (let (
    (document-data (map-get? document-vault { enterprise-id: enterprise-id, document-id: document-id }))
  )
    (if (is-none document-data)
      ERR-DOCUMENT-NOT-FOUND
      (if (not (has-permission enterprise-id document-id tx-sender PERMISSION-MANAGE))
        ERR-UNAUTHORIZED
        (begin
          (map-set document-vault
            { enterprise-id: enterprise-id, document-id: document-id }
            (merge (unwrap-panic document-data) { active: false })
          )
          (log-audit-event enterprise-id document-id tx-sender ACTION-UPDATE u"Document deleted")
          (ok true)
        )
      )
    )
  )
)

;; Read-Only Query Functions

;; Get Enterprise Information
(define-read-only (get-enterprise-info (enterprise-id (string-ascii 64)))
  (map-get? enterprise-registry { enterprise-id: enterprise-id })
)

;; Get Document Information
(define-read-only (get-document-info (enterprise-id (string-ascii 64)) (document-id (string-ascii 64)))
  (map-get? document-vault { enterprise-id: enterprise-id, document-id: document-id })
)

;; Get User Permission Level
(define-read-only (get-user-permission (enterprise-id (string-ascii 64)) (document-id (string-ascii 64)) (user principal))
  (let (
    (enterprise-data (map-get? enterprise-registry { enterprise-id: enterprise-id }))
    (permission-data (map-get? document-access-control { enterprise-id: enterprise-id, document-id: document-id, user: user }))
  )
    (if (is-none enterprise-data)
      (ok PERMISSION-NONE)
      (if (is-eq (get owner (unwrap-panic enterprise-data)) user)
        (ok PERMISSION-FULL)
        (if (is-none permission-data)
          (ok PERMISSION-NONE)
          (ok (get permission-level (unwrap-panic permission-data)))
        )
      )
    )
  )
)

;; Get Audit Log Entry
(define-read-only (get-audit-log-entry (enterprise-id (string-ascii 64)) (document-id (string-ascii 64)) (log-id uint))
  (map-get? document-audit-trail { enterprise-id: enterprise-id, document-id: document-id, log-id: log-id })
)

;; Utility Conversion Functions

;; Convert Uint to ASCII String
(define-private (uint-to-ascii (value uint))
  (concat "u" (int-to-ascii value))
)

;; Convert Int to ASCII String (Simplified)
(define-private (int-to-ascii (value uint))
  (unwrap-panic (element-at 
    (list "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "10" "11" "12" "13" "14" "15")
    (if (> value u15) u0 value)
  ))
)

;; Convert Principal to Buffer (Placeholder)
(define-private (principal-to-buff32 (user principal))
  (begin
    (ok 0x0000000000000000000000000000000000000000000000000000000000000000)
  )
)