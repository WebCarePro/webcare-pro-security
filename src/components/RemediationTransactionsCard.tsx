import React, { useState, useEffect } from 'react';
import { History, RotateCcw, Clock, ShieldCheck, AlertTriangle, RefreshCw, CheckCircle2, FileText, Database, Users, UserCheck, Trash2, BellOff } from 'lucide-react';
import { InlineConfirmPopover } from './InlineConfirmPopover';
import { showConfirm } from '../utils/dialog';

interface RemediationTransaction {
  tx_id: string;
  title: string;
  reason: string;
  status: 'completed' | 'rolled_back' | 'in_progress';
  created_at: string;
  timestamp: number;
  created_by: string;
  files_count: number;
  db_count: number;
  users_count?: number;
  total_items: number;
  rolled_back_at?: string;
  rolled_back_by?: string;
  sample_targets?: string[];
}

interface UserBackup {
  backup_file: string;
  user_id: number;
  user_login: string;
  user_email: string;
  display_name: string;
  roles: string[];
  created_at: string;
  timestamp: number;
  action_context: string;
  is_in_db?: boolean;
}

interface RemediationTransactionsCardProps {
  apiRequest: (options: any) => Promise<any>;
  onRollbackComplete?: () => void;
}

export const RemediationTransactionsCard: React.FC<RemediationTransactionsCardProps> = ({
  apiRequest,
  onRollbackComplete,
}) => {
  const [transactions, setTransactions] = useState<RemediationTransaction[]>([]);
  const [userBackups, setUserBackups] = useState<UserBackup[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [rollingBackId, setRollingBackId] = useState<string | null>(null);
  const [restoringUserId, setRestoringUserId] = useState<number | null>(null);
  const [restoringAllUsers, setRestoringAllUsers] = useState<boolean>(false);
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const fetchTransactions = async () => {
    setLoading(true);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/transactions/list',
        method: 'GET',
      });
      if (res?.success && Array.isArray(res?.transactions)) {
        setTransactions(res.transactions);
      }
    } catch (err) {
      console.error('Failed to fetch remediation transactions:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchUserBackups = async () => {
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/users/backups',
        method: 'GET',
      });
      if (res?.success && Array.isArray(res?.backups)) {
        setUserBackups(res.backups);
      }
    } catch (err) {
      console.error('Failed to fetch user backups:', err);
    }
  };

  useEffect(() => {
    fetchTransactions();
    fetchUserBackups();
  }, []);

  const handleRollback = async (txId: string) => {
    const confirmed = await showConfirm({
      title: 'Rollback Transaction',
      message: `Are you sure you want to perform 1-CLICK SAFE ROLLBACK for transaction:\n${txId}?\n\nThis will restore all pre-remediation files byte-for-byte, re-apply original permissions, restore modified database records, and reactivate deleted administrator accounts.`,
      confirmLabel: 'Execute Rollback',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }

    setRollingBackId(txId);
    setMsg(null);

    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/transactions/rollback',
        method: 'POST',
        data: { tx_id: txId },
      });

      if (res?.success) {
        setMsg({ type: 'success', text: res.message || 'Transaction successfully rolled back!' });
        fetchTransactions();
        fetchUserBackups();
        if (onRollbackComplete) {
          onRollbackComplete();
        }
      } else {
        setMsg({ type: 'error', text: res?.message || 'Rollback failed.' });
      }
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.message || 'Network error during rollback.' });
    } finally {
      setRollingBackId(null);
    }
  };

  const handleRestoreUser = async (backup: UserBackup) => {
    const confirmed = await showConfirm({
      title: 'Restore Administrator Account',
      message: `Restore administrator account '${backup.user_login}' (ID #${backup.user_id})?\n\nThis will immediately restore the account with its original password, email (${backup.user_email}), and full administrative capabilities.`,
      confirmLabel: 'Restore Account',
      variant: 'info',
    });
    if (!confirmed) {
      return;
    }

    setRestoringUserId(backup.user_id);
    setMsg(null);

    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/users/restore',
        method: 'POST',
        data: { backup_file: backup.backup_file },
      });

      if (res?.success) {
        setMsg({
          type: 'success',
          text: res.message || `User account '${backup.user_login}' restored successfully!`,
        });
        fetchUserBackups();
        if (onRollbackComplete) {
          onRollbackComplete();
        }
      } else {
        setMsg({ type: 'error', text: res?.message || 'Failed to restore user account.' });
      }
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.message || 'Network error restoring user account.' });
    } finally {
      setRestoringUserId(null);
    }
  };

  const handleRestoreAllUsers = async () => {
    const confirmed = await showConfirm({
      title: 'Restore All Quarantined Users',
      message: `Restore all ${userBackups.length} quarantined user accounts?\n\nAll accounts will be restored with their original roles, password hashes, and capabilities.`,
      confirmLabel: 'Restore All Accounts',
      variant: 'warning',
    });
    if (!confirmed) {
      return;
    }

    setRestoringAllUsers(true);
    setMsg(null);

    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/users/restore',
        method: 'POST',
        data: { all: true },
      });

      if (res?.success) {
        setMsg({ type: 'success', text: res.message || 'All user accounts restored successfully!' });
        fetchUserBackups();
        if (onRollbackComplete) {
          onRollbackComplete();
        }
      } else {
        setMsg({ type: 'error', text: res?.message || 'Failed to restore user accounts.' });
      }
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.message || 'Network error restoring user accounts.' });
    } finally {
      setRestoringAllUsers(false);
    }
  };

  const handleDismissUserBackup = async (backup: UserBackup) => {
    setMsg(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/users/backups/dismiss',
        method: 'POST',
        data: {
          backup_file: backup.backup_file,
          user_login: backup.user_login,
          user_id: backup.user_id,
        },
      });

      if (res?.success) {
        setMsg({
          type: 'success',
          text: `Dismissed notifications for '${backup.user_login}'. The top screen notice is silenced.`,
        });
        fetchUserBackups();
        if (onRollbackComplete) {
          onRollbackComplete();
        }
      } else {
        setMsg({ type: 'error', text: res?.message || 'Failed to dismiss notification.' });
      }
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.message || 'Network error dismissing notification.' });
    }
  };

  const handleDeleteUserBackup = async (backup: UserBackup) => {
    setMsg(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/users/backups/delete',
        method: 'POST',
        data: { backup_file: backup.backup_file },
      });

      if (res?.success) {
        setMsg({
          type: 'success',
          text: `Backup snapshot for '${backup.user_login}' deleted permanently.`,
        });
        fetchUserBackups();
        if (onRollbackComplete) {
          onRollbackComplete();
        }
      } else {
        setMsg({ type: 'error', text: res?.message || 'Failed to delete user backup.' });
      }
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.message || 'Network error deleting user backup.' });
    }
  };

  const handleDismissAllMissing = async () => {
    setMsg(null);
    try {
      const res = await apiRequest({
        path: '/webcare-pro-security/v1/users/backups/dismiss',
        method: 'POST',
        data: { all: true },
      });

      if (res?.success) {
        setMsg({
          type: 'success',
          text: 'Dismissed all missing user recovery notifications across the site.',
        });
        fetchUserBackups();
        if (onRollbackComplete) {
          onRollbackComplete();
        }
      } else {
        setMsg({ type: 'error', text: res?.message || 'Failed to dismiss notifications.' });
      }
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.message || 'Network error dismissing notifications.' });
    }
  };

  return (
    <div
      className="webcare-forensics-subcard"
      style={{
        borderRadius: '14px',
        padding: '24px',
      }}
    >
      {/* Header */}
      <div
        className="webcare-forensics-subcard-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
          paddingBottom: '18px',
          marginBottom: '20px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div
            style={{
              width: '44px',
              height: '44px',
              borderRadius: '10px',
              background: 'rgba(37, 99, 235, 0.15)',
              border: '1px solid rgba(37, 99, 235, 0.3)',
              color: '#3b82f6',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <Clock size={22} color="#3b82f6" />
          </div>
          <div>
            <h3 className="webcare-forensics-subcard-title" style={{ margin: 0, fontSize: '18px', fontWeight: 800 }}>
              Attack-Chain Transactional Snapshots & Safe Rollback
            </h3>
            <p className="webcare-forensics-subcard-desc" style={{ margin: '4px 0 0 0', fontSize: '13px' }}>
              Atomic pre-remediation snapshots enabling 1-click byte-for-byte file and database recovery
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={fetchTransactions}
          disabled={loading}
          className="webcare-btn"
          style={{
            background: '#f8fafc',
            color: '#334155',
            border: '1px solid #cbd5e1',
            padding: '7px 14px',
            borderRadius: '8px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: loading ? 'not-allowed' : 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <RefreshCw size={13} className={loading ? 'webcare-spin' : ''} />
          <span>Refresh History</span>
        </button>
      </div>

      {msg && (
        <div
          style={{
            marginBottom: '16px',
            padding: '12px 16px',
            borderRadius: '8px',
            fontSize: '13px',
            fontWeight: 600,
            background: msg.type === 'success' ? '#ecfdf5' : '#fef2f2',
            border: msg.type === 'success' ? '1px solid #a7f3d0' : '1px solid #fecaca',
            color: msg.type === 'success' ? '#047857' : '#b91c1c',
          }}
        >
          {msg.text}
        </div>
      )}

      {/* Quarantined / Backed-Up User Accounts Recovery Banner */}
      {userBackups.length > 0 && (() => {
        const missingCount = userBackups.filter((u) => !u.is_in_db).length;
        const allRestored = missingCount === 0;

        return (
          <div
            style={{
              marginBottom: '24px',
              background: allRestored ? '#f8fafc' : '#f0fdf4',
              border: allRestored ? '1px solid #e2e8f0' : '1px solid #86efac',
              borderRadius: '12px',
              padding: '20px',
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '12px',
                marginBottom: '16px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '36px',
                    height: '36px',
                    borderRadius: '8px',
                    background: allRestored ? '#f1f5f9' : '#dcfce7',
                    border: allRestored ? '1px solid #e2e8f0' : '1px solid #bbf7d0',
                    color: allRestored ? '#64748b' : '#16a34a',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Users size={18} color={allRestored ? '#64748b' : '#16a34a'} />
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 800, color: allRestored ? '#1e293b' : '#14532d' }}>
                      Quarantined / Backed-Up User Accounts ({userBackups.length})
                    </h4>
                    {allRestored && (
                      <span
                        style={{
                          background: '#ecfdf5',
                          color: '#059669',
                          border: '1px solid #a7f3d0',
                          fontSize: '11px',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '10px',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                        }}
                      >
                        <CheckCircle2 size={12} color="#16a34a" />
                        All Restored & Active
                      </span>
                    )}
                  </div>
                  <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: allRestored ? '#64748b' : '#166534' }}>
                    {allRestored
                      ? 'All backed-up administrator accounts have been restored and are active in WordPress.'
                      : `${missingCount} account(s) ready for restoration back into WordPress.`}
                  </p>
                </div>
              </div>

              {!allRestored ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    onClick={handleRestoreAllUsers}
                    disabled={restoringAllUsers}
                    className="webcare-btn"
                    style={{
                      background: '#16a34a',
                      color: '#ffffff',
                      border: 'none',
                      padding: '8px 16px',
                      borderRadius: '8px',
                      fontSize: '12px',
                      fontWeight: 700,
                      cursor: restoringAllUsers ? 'not-allowed' : 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      boxShadow: '0 2px 6px rgba(22, 163, 74, 0.25)',
                    }}
                  >
                    <RotateCcw size={13} className={restoringAllUsers ? 'webcare-spin' : ''} />
                    <span>{restoringAllUsers ? 'Restoring All...' : `Restore Missing (${missingCount}) Accounts`}</span>
                  </button>
                  <InlineConfirmPopover
                    buttonLabel="Dismiss All Alerts"
                    confirmLabel="Dismiss All Alerts"
                    question="Dismiss notifications for all missing accounts?"
                    consequence="This silences the top WordPress admin recovery banner permanently. Backups will remain safely stored."
                    variant="warning"
                    buttonIcon={<BellOff size={13} />}
                    buttonClass="webcare-btn-secondary"
                    buttonStyle={{
                      padding: '8px 14px',
                      borderRadius: '8px',
                      fontSize: '12px',
                      fontWeight: 600,
                    }}
                    onConfirm={handleDismissAllMissing}
                  />
                </div>
              ) : (
                <span
                  style={{
                    background: '#f1f5f9',
                    color: '#475569',
                    border: '1px solid #cbd5e1',
                    padding: '6px 12px',
                    borderRadius: '8px',
                    fontSize: '12px',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  <UserCheck size={14} color="#16a34a" />
                  <span>Active in Database</span>
                </span>
              )}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {userBackups.map((ub) => {
                const isRestored = !!ub.is_in_db;
                return (
                  <div
                    key={ub.backup_file}
                    style={{
                      background: '#ffffff',
                      border: isRestored ? '1px solid #e2e8f0' : '1px solid #bbf7d0',
                      borderRadius: '8px',
                      padding: '12px 16px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '12px',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '14px', fontWeight: 800, color: '#0f172a' }}>
                          {ub.user_login}
                        </span>
                        <span style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace' }}>
                          (ID #{ub.user_id})
                        </span>
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '1px 6px',
                            borderRadius: '4px',
                            background: '#dbeafe',
                            color: '#1d4ed8',
                            textTransform: 'uppercase',
                          }}
                        >
                          {ub.roles.join(', ') || 'Administrator'}
                        </span>
                        {isRestored && (
                          <span
                            style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              color: '#15803d',
                              background: '#ecfdf5',
                              border: '1px solid #a7f3d0',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                            }}
                          >
                            <CheckCircle2 size={12} color="#16a34a" />
                            Already Restored & Active
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '12px', color: '#475569', marginTop: '2px' }}>
                        Email: <strong>{ub.user_email}</strong> &bull; Backed up: {ub.created_at}
                      </div>
                    </div>

                    {isRestored ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span
                          style={{
                            fontSize: '12px',
                            fontWeight: 600,
                            color: '#16a34a',
                            background: '#f0fdf4',
                            border: '1px solid #bbf7d0',
                            padding: '5px 10px',
                            borderRadius: '6px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                        >
                          <CheckCircle2 size={13} color="#16a34a" />
                          Restored & Active
                        </span>
                        <button
                          type="button"
                          onClick={() => handleRestoreUser(ub)}
                          disabled={restoringUserId === ub.user_id}
                          className="webcare-btn"
                          title="Re-apply or overwrite snapshot to database"
                          style={{
                            background: '#f8fafc',
                            color: '#64748b',
                            border: '1px solid #cbd5e1',
                            padding: '5px 10px',
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 600,
                            cursor: restoringUserId === ub.user_id ? 'not-allowed' : 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                        >
                          <RotateCcw size={11} className={restoringUserId === ub.user_id ? 'webcare-spin' : ''} />
                          <span>Re-apply Snapshot</span>
                        </button>

                        <InlineConfirmPopover
                          buttonLabel="Permanent Remove"
                          confirmLabel="Yes, Permanently Remove"
                          question={`Permanently delete backup snapshot for '${ub.user_login}'?`}
                          consequence="This file will be completely erased from disk and cannot be restored."
                          variant="danger"
                          buttonIcon={<Trash2 size={12} />}
                          buttonClass="webcare-btn-secondary"
                          buttonStyle={{
                            color: '#dc2626',
                            borderColor: '#fca5a5',
                            background: '#fff',
                            padding: '5px 12px',
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 700,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                          onConfirm={() => handleDeleteUserBackup(ub)}
                        />
                      </div>
                    ) : (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <button
                          type="button"
                          onClick={() => handleRestoreUser(ub)}
                          disabled={restoringUserId === ub.user_id}
                          className="webcare-btn"
                          style={{
                            background: '#22c55e',
                            color: '#ffffff',
                            border: 'none',
                            padding: '6px 14px',
                            borderRadius: '6px',
                            fontSize: '12px',
                            fontWeight: 700,
                            cursor: restoringUserId === ub.user_id ? 'not-allowed' : 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px',
                            boxShadow: '0 2px 6px rgba(34, 197, 94, 0.25)',
                          }}
                        >
                          <RotateCcw size={12} className={restoringUserId === ub.user_id ? 'webcare-spin' : ''} />
                          <span>{restoringUserId === ub.user_id ? 'Restoring...' : '1-Click Restore Account'}</span>
                        </button>

                        <InlineConfirmPopover
                          buttonLabel="Dismiss Alert"
                          confirmLabel="Dismiss Alert"
                          question={`Dismiss notification for '${ub.user_login}'?`}
                          consequence="The top screen recovery notification will be permanently silenced for this account. The backup snapshot will remain safely stored."
                          variant="warning"
                          buttonIcon={<BellOff size={11} />}
                          buttonClass="webcare-btn-secondary"
                          buttonStyle={{
                            padding: '6px 12px',
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 600,
                          }}
                          onConfirm={() => handleDismissUserBackup(ub)}
                        />

                        <InlineConfirmPopover
                          buttonLabel="Permanent Remove"
                          confirmLabel="Yes, Permanently Remove"
                          question={`Permanently delete backup snapshot for '${ub.user_login}'?`}
                          consequence="This file will be completely erased from disk and cannot be restored."
                          variant="danger"
                          buttonIcon={<Trash2 size={12} />}
                          buttonClass="webcare-btn-secondary"
                          buttonStyle={{
                            color: '#dc2626',
                            borderColor: '#fca5a5',
                            background: '#fff',
                            padding: '6px 14px',
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 700,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                          onConfirm={() => handleDeleteUserBackup(ub)}
                        />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {/* Transaction List */}
      <div>
        {loading ? (
          <div style={{ padding: '40px 0', textAlign: 'center', color: '#64748b', fontSize: '13px' }}>
            <RefreshCw size={24} className="webcare-spin" style={{ margin: '0 auto 10px', display: 'block', color: '#3b82f6' }} />
            Loading remediation transaction history...
          </div>
        ) : transactions.length === 0 ? (
          <div
            style={{
              padding: '40px 20px',
              textAlign: 'center',
              borderRadius: '10px',
              background: '#f8fafc',
              border: '1px dashed #cbd5e1',
            }}
          >
            <Clock size={36} color="#94a3b8" style={{ margin: '0 auto 10px', display: 'block' }} />
            <p style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: '#334155' }}>
              No remediation transactions on record yet.
            </p>
            <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: '#64748b' }}>
              Whenever you eradicate attack chains, quarantine files, or repair vulnerabilities, atomic backups are recorded here automatically.
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {transactions.map((tx) => {
              const isRolledBack = tx.status === 'rolled_back';

              return (
                <div
                  key={tx.tx_id}
                  style={{
                    background: isRolledBack ? '#f8fafc' : '#ffffff',
                    border: isRolledBack ? '1px solid #e2e8f0' : '1px solid #cbd5e1',
                    borderRadius: '10px',
                    padding: '16px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '14px',
                  }}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1, minWidth: '240px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span style={{ fontFamily: 'monospace', fontSize: '12px', fontWeight: 700, color: '#0284c7' }}>
                        {tx.tx_id}
                      </span>
                      <span
                        style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '6px',
                          textTransform: 'uppercase',
                          background: isRolledBack ? '#fef3c7' : '#ecfdf5',
                          border: isRolledBack ? '1px solid #fde68a' : '1px solid #a7f3d0',
                          color: isRolledBack ? '#b45309' : '#047857',
                        }}
                      >
                        {isRolledBack ? 'Rolled Back' : 'Active Snapshot'}
                      </span>
                      <span style={{ fontSize: '12px', color: '#64748b' }}>
                        {tx.files_count} file(s) &bull; {tx.db_count} DB record(s)
                        {(tx.users_count || 0) > 0 ? ` • ${tx.users_count} user(s)` : ''}
                      </span>
                    </div>

                    <div style={{ fontSize: '14px', fontWeight: 700, color: '#0f172a' }}>{tx.title}</div>
                    <div style={{ fontSize: '12px', color: '#475569' }}>{tx.reason}</div>

                    {tx.sample_targets && tx.sample_targets.length > 0 && (
                      <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                        Targets: {tx.sample_targets.join(', ')}
                      </div>
                    )}

                    <div style={{ fontSize: '11px', color: '#94a3b8', display: 'flex', gap: '12px', flexWrap: 'wrap', marginTop: '4px' }}>
                      <span>Created: {tx.created_at} by {tx.created_by}</span>
                      {tx.rolled_back_at && (
                        <span style={{ color: '#d97706', fontWeight: 600 }}>
                          Rolled back: {tx.rolled_back_at} by {tx.rolled_back_by}
                        </span>
                      )}
                    </div>
                  </div>

                  <div>
                    {!isRolledBack ? (
                      <button
                        type="button"
                        onClick={() => handleRollback(tx.tx_id)}
                        disabled={rollingBackId === tx.tx_id}
                        className="webcare-btn"
                        style={{
                          background: '#fffbeb',
                          color: '#b45309',
                          border: '1px solid #fde68a',
                          padding: '7px 14px',
                          borderRadius: '8px',
                          fontSize: '12px',
                          fontWeight: 700,
                          cursor: rollingBackId === tx.tx_id ? 'not-allowed' : 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                        }}
                      >
                        <RotateCcw size={13} className={rollingBackId === tx.tx_id ? 'webcare-spin' : ''} />
                        <span>{rollingBackId === tx.tx_id ? 'Rolling Back...' : '1-Click Safe Rollback'}</span>
                      </button>
                    ) : (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <span
                          style={{
                            fontSize: '12px',
                            fontWeight: 600,
                            color: 'var(--webcare-text-muted, #64748b)',
                            padding: '5px 10px',
                            borderRadius: '6px',
                            background: 'var(--webcare-bg-elevated, #f1f5f9)',
                            border: '1px solid var(--webcare-border, #e2e8f0)',
                          }}
                        >
                          Restored & Archived
                        </span>
                        {userBackups.some((u) => !u.is_in_db) && (
                          <button
                            type="button"
                            onClick={() => handleRollback(tx.tx_id)}
                            disabled={rollingBackId === tx.tx_id}
                            className="webcare-btn"
                            style={{
                              background: '#22c55e',
                              color: '#ffffff',
                              border: 'none',
                              padding: '5px 12px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 700,
                              cursor: rollingBackId === tx.tx_id ? 'not-allowed' : 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '5px',
                            }}
                          >
                            <RotateCcw size={11} className={rollingBackId === tx.tx_id ? 'webcare-spin' : ''} />
                            <span>{rollingBackId === tx.tx_id ? 'Restoring Accounts...' : 'Restore Missing Accounts'}</span>
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
