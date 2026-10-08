import { useEffect, useState } from 'react';
export default function Table() {
  const [rows, setRows] = useState<number[]>([]);
  useEffect(() => { fetch('/api/data').then(r => r.json()).then(d => setRows(d.rows)); }, []);
  return <ul onClick={() => setRows([])}>{rows.map(r => <li key={r}>{r}</li>)}</ul>;
}
