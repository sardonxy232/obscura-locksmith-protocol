;; Content Vault & Verification System
;; Secure content management platform with cryptographic authentication
;; 
;; Advanced blockchain-based solution for content registration and tracking
;; Incorporates multi-layered security protocols with granular permission controls
;; Delivers persistent storage solutions for digital media with enhanced metadata processing
;; Includes comprehensive validation engines and detailed error handling mechanisms

;; ===== Core system configuration variables and management settings =====

;; Supreme authority for content vault operations
(define-constant vault-supreme-authority tx-sender)

;; ===== Detailed error classification system for comprehensive exception management =====

;; Content-specific error classifications with precise categorization
(define-constant content-missing-error (err u401))
(define-constant duplicate-content-error (err u402))
(define-constant metadata-invalid-error (err u403))
(define-constant size-limit-exceeded-error (err u404))
(define-constant unauthorized-access-error (err u405))
(define-constant owner-mismatch-error (err u406))
(define-constant admin-rights-needed-error (err u400))
(define-constant visibility-blocked-error (err u407))
(define-constant tag-format-error (err u408))
(define-constant invalid-permission-grant-error (err u409))
(define-constant permission-duplicate-error (err u410))

;; ===== System state tracking variables =====

;; Incremental counter for content item identification
(define-data-var content-vault-sequence uint u0)

;; ===== Primary data architecture definitions =====

;; Main content storage vault with detailed metadata framework
(define-map content-vault-database
  { content-id-key: uint }
  {
    content-title: (string-ascii 64),
    content-creator: principal,
    content-bytes: uint,
    creation-timestamp: uint,
    content-summary: (string-ascii 128),
    content-labels: (list 10 (string-ascii 32))
  }
)

;; Sophisticated authorization framework with detailed access management
(define-map user-permission-database
  { content-id-key: uint, authorized-user: principal }
  { permission-granted: bool }
)

;; ===== Internal helper functions for validation and data processing =====

;; Single label format verification with thorough constraint checking
(define-private (verify-single-label-format (label-input (string-ascii 32)))
  (and
    (> (len label-input) u0)
    (< (len label-input) u33)
  )
)

;; Full label collection verification with data integrity checks
(define-private (verify-label-collection-integrity (label-collection (list 10 (string-ascii 32))))
  (and
    (> (len label-collection) u0)
    (<= (len label-collection) u10)
    (is-eq (len (filter verify-single-label-format label-collection)) (len label-collection))
  )
)

;; Content presence verification within vault database
(define-private (verify-content-presence (content-id-key uint))
  (is-some (map-get? content-vault-database { content-id-key: content-id-key }))
)

;; Content size data extraction utility for registered items
(define-private (extract-content-size-data (content-id-key uint))
  (default-to u0
    (get content-bytes
      (map-get? content-vault-database { content-id-key: content-id-key })
    )
  )
)

;; Thorough ownership validation mechanism with principal verification
(define-private (validate-content-ownership (content-id-key uint) (principal-to-verify principal))
  (match (map-get? content-vault-database { content-id-key: content-id-key })
    content-record (is-eq (get content-creator content-record) principal-to-verify)
    false
  )
)

;; Helper function for calculating storage usage by owner
(define-private (calculate-owner-storage-usage (content-id uint))
  (match (map-get? content-vault-database { content-id-key: content-id })
    content-record (if (is-eq (get content-creator content-record) tx-sender)
                     (get content-bytes content-record)
                     u0)
    u0
  )
)

;; ===== Main public interface functions for external interactions =====

;; Complete content registration with extensive validation procedures
(define-public (create-new-content-entry
  (content-title (string-ascii 64))
  (content-bytes uint)
  (content-summary (string-ascii 128))
  (content-labels (list 10 (string-ascii 32)))
)
  (let
    (
      (next-content-id (+ (var-get content-vault-sequence) u1))
    )
    ;; Thorough input validation with comprehensive error handling
    (asserts! (> (len content-title) u0) metadata-invalid-error)
    (asserts! (< (len content-title) u65) metadata-invalid-error)
    (asserts! (> content-bytes u0) size-limit-exceeded-error)
    (asserts! (< content-bytes u1000000000) size-limit-exceeded-error)
    (asserts! (> (len content-summary) u0) metadata-invalid-error)
    (asserts! (< (len content-summary) u129) metadata-invalid-error)
    (asserts! (verify-label-collection-integrity content-labels) tag-format-error)

    ;; Perform secure content registration in vault database
    (map-insert content-vault-database
      { content-id-key: next-content-id }
      {
        content-title: content-title,
        content-creator: tx-sender,
        content-bytes: content-bytes,
        creation-timestamp: block-height,
        content-summary: content-summary,
        content-labels: content-labels
      }
    )

    ;; Establish initial access permissions for content creator
    (map-insert user-permission-database
      { content-id-key: next-content-id, authorized-user: tx-sender }
      { permission-granted: true }
    )

    ;; Increment the global content sequence counter
    (var-set content-vault-sequence next-content-id)
    (ok next-content-id)
  )
)

;; Secure ownership transfer mechanism with validation protocols
(define-public (transfer-content-ownership (content-id-key uint) (recipient-principal principal))
  (let
    (
      (current-content-record (unwrap! (map-get? content-vault-database { content-id-key: content-id-key })
        content-missing-error))
    )
    ;; Strict ownership verification before transfer execution
    (asserts! (verify-content-presence content-id-key) content-missing-error)
    (asserts! (is-eq (get content-creator current-content-record) tx-sender) owner-mismatch-error)

    ;; Execute secure ownership transfer with updated creator information
    (map-set content-vault-database
      { content-id-key: content-id-key }
      (merge current-content-record { content-creator: recipient-principal })
    )
    (ok true)
  )
)

;; Irreversible content deletion with comprehensive security validation
(define-public (delete-content-permanently (content-id-key uint))
  (let
    (
      (content-for-deletion (unwrap! (map-get? content-vault-database { content-id-key: content-id-key })
        content-missing-error))
    )
    ;; Rigorous ownership verification before permanent deletion
    (asserts! (verify-content-presence content-id-key) content-missing-error)
    (asserts! (is-eq (get content-creator content-for-deletion) tx-sender) owner-mismatch-error)

    ;; Execute irreversible content removal from vault database
    (map-delete content-vault-database { content-id-key: content-id-key })
    (ok true)
  )
)

;; ===== Query functions for external data retrieval with access control =====

;; Comprehensive content data retrieval with permission enforcement
(define-read-only (fetch-content-details (content-id-key uint))
  (let
    (
      (content-record (unwrap! (map-get? content-vault-database { content-id-key: content-id-key })
        content-missing-error))
      (user-has-access (default-to false
        (get permission-granted
          (map-get? user-permission-database { content-id-key: content-id-key, authorized-user: tx-sender })
        )
      ))
    )
    ;; Verify content existence and access authorization before data retrieval
    (asserts! (verify-content-presence content-id-key) content-missing-error)
    (asserts! (or user-has-access (is-eq (get content-creator content-record) tx-sender)) visibility-blocked-error)

    ;; Return detailed content information structure
    (ok {
      content-title: (get content-title content-record),
      content-creator: (get content-creator content-record),
      content-bytes: (get content-bytes content-record),
      creation-timestamp: (get creation-timestamp content-record),
      content-summary: (get content-summary content-record),
      content-labels: (get content-labels content-record)
    })
  )
)

;; System statistics and administrative data retrieval
(define-read-only (fetch-vault-statistics)
  (ok {
    total-content-items: (var-get content-vault-sequence),
    vault-administrator: vault-supreme-authority
  })
)

;; Content ownership information utility for external verification
(define-read-only (fetch-content-owner-data (content-id-key uint))
  (match (map-get? content-vault-database { content-id-key: content-id-key })
    content-entry (ok (get content-creator content-entry))
    content-missing-error
  )
)

;; Detailed permission status verification with comprehensive reporting
(define-read-only (verify-user-permissions (content-id-key uint) (user-to-check principal))
  (let
    (
      (content-entry (unwrap! (map-get? content-vault-database { content-id-key: content-id-key })
        content-missing-error))
      (explicit-permission (default-to false
        (get permission-granted
          (map-get? user-permission-database { content-id-key: content-id-key, authorized-user: user-to-check })
        )
      ))
    )
    ;; Return detailed permission status information
    (ok {
      has-explicit-permission: explicit-permission,
      is-content-owner: (is-eq (get content-creator content-entry) user-to-check),
      can-access-content: (or explicit-permission (is-eq (get content-creator content-entry) user-to-check))
    })
  )
)

;; Simple content existence verification (straightforward presence check)
(define-read-only (check-content-existence (content-id-key uint))
  (ok (verify-content-presence content-id-key))
)
