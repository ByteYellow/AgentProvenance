import unittest
from pathlib import Path
from html_assets import hosted_page


class HostedTourAssets(unittest.TestCase):
    def test_unchanged_content_and_idempotent_assets(self):
        page, assets = Path("site/en/index.html"), Path("site/tour-assets")
        raw = '<html>\n<HEAD><base href="../"><script>const example="</head>"</script></HEAD>\n<body></body></html>'
        result = hosted_page(raw, page, assets)
        self.assertEqual(hosted_page(result, page, assets), result)
        self.assertIn('<script>const example="</head>"</script><link', result)
        self.assertIn('src="tour-assets/tour.js"', result)
        self.assertEqual(result.count('href="tour-assets/tour.css"'), 1)
        with self.assertRaises(ValueError):
            hosted_page(result.replace('</HEAD>', '<script src="tour-assets/tour.js"></script></HEAD>'), page, assets)

    def test_portable_reader_uses_local_assets(self):
        page = Path("site/current/browser/en/index.html")
        self.assertIn('src="../tour-assets/tour.js"', hosted_page('<head></head>', page, page.parents[1] / "tour-assets"))
