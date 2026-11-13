import type { GetServerSideProps } from "next";

// /profile?avatar=https://example.com/me.png  -- server inlines the avatar as base64
export const getServerSideProps: GetServerSideProps = async (ctx) => {
  const avatar = ctx.query.avatar as string;
  const res = await fetch(avatar); // VULN-EXPECTED
  const b64 = Buffer.from(await res.arrayBuffer()).toString("base64");
  return { props: { avatar: `data:image/png;base64,${b64}` } };
};

export default function Profile({ avatar }: { avatar: string }) {
  return <img src={avatar} alt="avatar" />;
}
