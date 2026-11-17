# Refined homepage preview

English | [中文](README.zh-CN.md)

An independent visual variant of the [existing homepage preview](../README.md).
It retains the AgentProvenance wordmark, four featured cases, three topics,
archive dialogs and reader links. Typography, spacing and evidence excerpts
are refined without changing the formal Dashboard or recording data.

## Build and review

First build and serve the existing homepage preview. Add this variant to that
same directory, keeping its original `index.html`:

```sh
python3 previews/v1.0-home/refined/build.py --site output/home-review
node previews/v1.0-home/refined/check.cjs http://127.0.0.1:58729/
```

Open `/refined.html?lang=en` for this design and `/?lang=en` for the previous
design. The page includes a link back to the previous design. Both share the
existing reader, documentation and downloads. Review covers Chinese/English,
four viewport widths, archive navigation, guide icons, focus restoration,
language switching and the direct comparison link.

The current repair comparison uses the saved inspection Run
`run-860466af8a9a` as A and repair Run `run-3bfc6838a9c6` as B. Historical
comparison pairs remain separate.

## Evidence imagery

The images are excerpts from saved public recordings: the file comparison,
workspace output-file table, browser screenshot and collaboration graph.
`media/sources.json` records their routes, references and image hashes. The
workspace excerpt selects the existing rendered change table. The browser
and graph images are cropped details. No actions or relationships are added.

To recapture them from a running preview:

```sh
node previews/v1.0-home/refined/capture.cjs http://127.0.0.1:58729/
```

This remains a local review variant. The formal build and online site are unchanged.
