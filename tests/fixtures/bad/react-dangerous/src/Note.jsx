export default function Note({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
