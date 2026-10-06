# ドキュメント一覧

[English](INDEX.md) | 日本語

最終確認日: 2026-09-29（現在の作業ツリーに対して確認）

[アカウント・グループのセキュリティと移行](./security/ACCOUNT_AND_GROUP_SECURITY.md)（英語）に、2026-09-16に実装した端末承認、透明性ログ、MLSのエポック、パスキー、履歴復元をまとめています。

実装、アーキテクチャ、セキュリティ、運用、復旧に関する資料の入口です。**implemented**（実装済み）と記載した内容は、リンク先のコードまたはテストで裏付けられています。**target**（目標）と記載した内容は、現時点で保証しているものではありません。

README と、利用者・運用者向けのガイド（デスクトップ、Android、運用、バックアップ、デプロイ）は日本語と英語の両方があり、日本語版のファイル名は `.ja.md` で終わります。設計記録や監査記録など開発者向けの資料は、作成時の言語のまま管理しています。下の一覧で「（英語）」と付けたものは英語のみです。

## はじめに

- [リポジトリの概要](../README.ja.md)
- [システム構成一覧](./SYSTEM_INVENTORY.md)（英語）
- [デスクトップクライアント](./DESKTOP.ja.md)
- [Androidクライアント](./ANDROID.ja.md)
- [アーキテクチャ](./policies/ARCHITECTURE.md)（英語）
- [既知の制限](./policies/LIMITATIONS.md)
- [リスク一覧](./RISK_REGISTER.md)（英語）
- [検証記録](./VERIFICATION.md)（英語）

## セキュリティ

- [audit-alparts の対応内容とデプロイ時の設定（2026-09-26）](./security/AUDIT_ALPARTS_REMEDIATION.md)
- [セキュリティポリシー](./policies/SECURITY.md)（英語）
- [脅威モデル](./security/THREAT_MODEL.md)（英語）
- [セキュリティ監査と Deep Security Scan の記録](./policies/SECURITY_AUDIT.md)
- [以前の脅威モデルへのリンク](./policies/THREAT_MODEL.md)

## 信頼性と運用

- [信頼性モデル](./policies/RELIABILITY.md)（英語）
- [障害モード分析](./reliability/FAILURE_MODES.md)（英語）
- [SLI/SLOの基準](./reliability/SLO.md)（英語）
- [運用方針](./policies/OPERATIONS.md)（英語）
- [運用者向けの詳しいガイド](./OPERATIONS.ja.md)
- [バックアップと復元](./BACKUP.ja.md)
- [災害復旧](./policies/DISASTER_RECOVERY.md)（英語）
- [インシデント対応手順](./runbooks/INCIDENT_RESPONSE.md)（英語）

## デプロイ

- [デプロイガイド](./policies/DEPLOYMENT.ja.md)
- [機能レベル](./deployment/CAPABILITY_LEVELS.md)（英語）
- [単一ホスト本番用のCompose構成](../compose.production.yml)
- [コンテナーのビルド](../Dockerfile)
- [アプリケーションのsystemdユニット](../deploy/alparts.service)
- [バックアップのサービスとタイマー](../deploy/alparts-backup.service)
- [開発専用の依存サービス](../docker-compose.yml)

## 設計判断（英語）

- [ADR一覧](./adr/README.md)
- [ストレージ](./adr/0001-storage.md)
- [一貫性](./adr/0002-consistency.md)
- [テナント分離](./adr/0003-tenancy.md)
- [デプロイと高可用性](./adr/0004-deployment-and-ha.md)
- [バックアップと復旧](./adr/0005-backup-and-recovery.md)
- [可観測性](./adr/0006-observability.md)
- [認証](./adr/0007-authentication.md)
- [認可](./adr/0008-authorization.md)
- [監査の外部証跡](./adr/0009-audit-witness.md)
- [スキーマとイメージの対応](./adr/0010-schema-image-coupling.md)

## インターフェースとソースコード

- [APIとWebSocketの一覧](./api/README.md)（英語）
- [サーバーのエントリーポイント](../packages/server/src/index.ts)
- [HTTPの構成](../packages/server/src/app.ts)
- [データベーススキーマ](../packages/server/src/db/schema.ts)
- [実行時のスキーマ検査](../packages/server/src/db/schema-catalog.ts)
- [共有のプロトコル型と正規化シリアライズ](../packages/shared/src)
- [Webクライアント](../packages/client/src)
- [Electronデスクトップクライアント](../packages/desktop/src)
- [データベースの移行](../packages/server/src/db/migrations)
- [バックアップ・復元スクリプト](../scripts)

## 開発

- [開発ガイドとリリース前の確認](./policies/CONTRIBUTING.md)（英語）
- [製品仕様（未実装の部分は目標）](./policies/SPECIFICATION.md)
- [実装の残作業](./policies/IMPLEMENTATION_TODO.md)

`SPECIFICATION.md` は、目指している製品全体を記述したものです。実装済みであることや準拠していることを示すものではありません。内容が食い違う場合は、実行可能なコードとテスト、そして現在の制限とリスク一覧が、実際に提供している範囲を表します。
