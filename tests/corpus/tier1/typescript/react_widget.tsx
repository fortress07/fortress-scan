import React from 'react';

export function Bio({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function SearchEcho() {
  const term = new URLSearchParams(window.location.search).get('q') || '';
  return <div dangerouslySetInnerHTML={{ __html: term }} />; // fsb-expect: FSB-XSS-001
}

export function SearchEchoSafe() {
  const term = new URLSearchParams(window.location.search).get('q') || '';
  return <div>{term}</div>;
}
