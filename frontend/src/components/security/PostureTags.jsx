import { Badge } from "../common/Badge.jsx";
import { tagTone, titleCase } from "../../utils/format.js";

export default function PostureTags({ tags = [] }) {
  if (!tags.length) return <div className="text-sm text-slate-400">No posture tags reported.</div>;
  return (
    <div className="flex flex-wrap gap-2">
      {tags.map((tag) => (
        <Badge key={`${tag.tag}-${tag.source}`} className={tagTone(tag.severity)}>
          {titleCase(tag.tag)}
        </Badge>
      ))}
    </div>
  );
}
