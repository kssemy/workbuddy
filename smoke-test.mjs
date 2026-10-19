import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

process.env.TZ = 'Asia/Seoul';
const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)].map(x => x[1]);
scripts.forEach(script => new vm.Script(script));

const app = scripts.at(-1);
const part = (start, end) => app.slice(app.indexOf(start), app.indexOf(end));
const context = { attendanceRows: [], overtimeRows: [], lastMembers: [] };
vm.runInNewContext(
  part('function fmtTime(', 'function getDaySchedule(') +
  part('function getDaySchedule(', 'function fillDaySchedules(') +
  part('function weekStart(', 'function updateWeeklyUI('), context
);

const member = {
  id: 'test', work_days: [1, 2, 3, 4, 5], day_schedules: {},
  work_start: '09:00', work_end: '18:00', lunch_start: '12:00', lunch_end: '13:00'
};
context.lastMembers.push(member);
const at = time => new Date(`2026-10-19T${time}+09:00`);
context.attendanceRows.push({
  member_id: 'test', work_date: '2026-10-19',
  started_at: at('09:00:00').toISOString(),
  last_seen_at: at('19:30:00').toISOString(),
  ended_at: at('19:30:00').toISOString()
});
assert.equal(context.scheduledWorkedMs(member, at('19:30:00')), 8 * 3600000);
context.overtimeRows.push({
  member_id: 'test', started_at: at('18:45:00').toISOString(),
  ended_at: at('19:15:00').toISOString()
});
assert.equal(context.overtimeMsFor('test', at('19:30:00')), 90 * 60000);

context.overtimeRows.length = 0;
context.attendanceRows[0].ended_at = null;
context.attendanceRows[0].last_seen_at = at('18:30:00').toISOString();
assert.equal(context.overtimeMsFor('test', at('20:00:00')), 30 * 60000 + 30000);
console.log('WorkBuddy smoke checks passed');
