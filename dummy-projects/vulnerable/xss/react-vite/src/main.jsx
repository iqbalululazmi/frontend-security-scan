import React from "react";
import { createRoot } from "react-dom/client";
import Search, { Banner } from "./Search.jsx";
import Comments from "./Comments.jsx";
import Redirect from "./Redirect.jsx";
import Messages from "./Messages.jsx";

createRoot(document.getElementById("root")).render(
  <>
    <Search />
    <Banner />
    <Comments comments={[{ id: 1, body: "<i>hello</i>" }]} />
    <Redirect />
    <Messages />
  </>
);
