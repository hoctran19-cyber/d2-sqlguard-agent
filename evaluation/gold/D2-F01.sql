-- Reference only: never sent to the agent.
SELECT SUM(amount_vnd) AS collected_vnd FROM payment WHERE status = 'successful' AND paid_at >= '2026-09-01' AND paid_at < '2026-10-01';
