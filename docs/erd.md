# ERD — vuln_mgmt

GitHub에서 Mermaid로 렌더링된다. 정의 원본은 `db/schema.sql`이며, 둘이 다르면 schema.sql이 맞다.

- **실제 데이터**(외부 수집): `software`, `vulnerabilities`, `cve_package_status`
- **가상 데이터**(운영 시뮬레이션): `systems`, `installed_software`, `staff`, `system_vulnerabilities`, `patch_history`

```mermaid
erDiagram
    software {
        INT software_id PK
        VARCHAR name UK "Apache HTTP Server"
        VARCHAR source_package UK "apache2, openssh"
    }

    vulnerabilities {
        VARCHAR cve_id PK "CHECK ^CVE-YYYY-NNNN+$"
        TEXT description
        DATE published_date
        DECIMAL cvss_score "NULL 허용, 0.0~10.0"
        VARCHAR cvss_version
        VARCHAR cvss_vector
        VARCHAR cvss_source
        ENUM ubuntu_priority "negligible~critical"
        VARCHAR source_url
        DATETIME created_at
    }

    cve_package_status {
        VARCHAR cve_id PK, FK
        INT software_id PK, FK
        VARCHAR ubuntu_release PK "24.04"
        ENUM status "needed, released, not-affected, deferred, ignored"
        VARCHAR fixed_version "released이면 필수"
        VARCHAR usn_id
        VARCHAR source_url
    }

    systems {
        INT system_id PK
        VARCHAR hostname UK
        VARCHAR ubuntu_release
        ENUM environment "prod, staging, dev"
        DATETIME created_at
    }

    installed_software {
        INT system_id PK, FK
        INT software_id PK, FK
        VARCHAR installed_version "Debian 버전 문자열"
        DATETIME collected_at
    }

    staff {
        INT staff_id PK
        VARCHAR name
        VARCHAR team
        VARCHAR email UK
    }

    system_vulnerabilities {
        INT sv_id PK
        INT system_id FK "UK(system_id, cve_id)"
        VARCHAR cve_id FK
        INT software_id FK "FK(system_id, software_id)"
        ENUM status "open, in_progress, patched, risk_accepted"
        INT assignee_id FK "NULL = 미배정"
        DATE due_date
        DATETIME detected_at
        DATETIME patched_at "patched이면 필수"
        INT updated_by FK "트리거가 changed_by로 사용"
        DATETIME updated_at
    }

    patch_history {
        INT history_id PK
        INT sv_id FK "ON DELETE CASCADE"
        ENUM old_status "최초 등록이면 NULL"
        ENUM new_status
        INT changed_by FK
        DATETIME changed_at
        VARCHAR note
    }

    vulnerabilities    ||--o{ cve_package_status     : "릴리스별 상태"
    software           ||--o{ cve_package_status     : "패키지"
    systems            ||--o{ installed_software     : "설치"
    software           ||--o{ installed_software     : "설치됨"
    installed_software ||--o{ system_vulnerabilities : "복합 FK (system_id, software_id)"
    vulnerabilities    ||--o{ system_vulnerabilities : "CVE"
    staff              |o--o{ system_vulnerabilities : "assignee_id"
    staff              |o--o{ system_vulnerabilities : "updated_by"
    system_vulnerabilities ||--o{ patch_history      : "이력 (CASCADE)"
    staff              |o--o{ patch_history          : "changed_by"
```

## 관계 요약

| 부모 | 자식 | FK 컬럼 | 카디널리티 | ON DELETE |
|---|---|---|---|---|
| vulnerabilities | cve_package_status | cve_id | 1 : N | RESTRICT |
| software | cve_package_status | software_id | 1 : N | RESTRICT |
| systems | installed_software | system_id | 1 : N | RESTRICT |
| software | installed_software | software_id | 1 : N | RESTRICT |
| installed_software | system_vulnerabilities | (system_id, software_id) | 1 : N | RESTRICT |
| vulnerabilities | system_vulnerabilities | cve_id | 1 : N | RESTRICT |
| staff | system_vulnerabilities | assignee_id (NULL 허용) | 0..1 : N | RESTRICT |
| staff | system_vulnerabilities | updated_by (NULL 허용) | 0..1 : N | RESTRICT |
| system_vulnerabilities | patch_history | sv_id | 1 : N | **CASCADE** |
| staff | patch_history | changed_by (NULL 허용) | 0..1 : N | RESTRICT |

`systems` ↔ `software`는 `installed_software`를 통한 M:N이고, `system_vulnerabilities`는
`installed_software`의 자식이므로 `system_id`, `software_id`는 각각 `systems`, `software`에도 간접적으로 묶인다.
