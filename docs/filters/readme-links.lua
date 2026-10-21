-- Rewrite relative links on the symlinked example README pages.
--
-- Each page under docs/examples/ is a symlink to
-- src/inspect_ranges/examples/_<name>/README.md (the page name is the
-- directory name without its leading underscore), so relative links that
-- resolve naturally on GitHub (notes.md, range.yaml, recipes/) point at
-- nothing in the rendered site. This filter rewrites them to the
-- repository: blob URLs for files, tree URLs for directories, raw URLs for
-- images. A link that resolves to another example's README stays in-site as
-- that example's doc page.

local REPO = "https://github.com/meridianlabs-ai/inspect_ranges"
local RAW = "https://raw.githubusercontent.com/meridianlabs-ai/inspect_ranges"
local EXAMPLES = "src/inspect_ranges/examples"

local function example_name()
  local input = (quarto and quarto.doc and quarto.doc.input_file)
      or PANDOC_STATE.input_files[1]
  return pandoc.path.filename(input):gsub("%.md$", "")
end

local name = example_name()
-- the package directory for this page: the page name, underscore-prefixed
local dir = "_" .. name

local function is_relative(target)
  return not (target:match("^%a[%w+.%-]*:") or target:match("^#") or target:match("^/"))
end

-- Resolve a link target against the README's true repo location,
-- collapsing any ../ segments.
local function repo_path(target)
  local path = EXAMPLES .. "/" .. dir .. "/" .. target:gsub("^%./", "")
  local prev
  repeat
    prev = path
    path = path:gsub("[^/]+/%.%./", "", 1)
  until path == prev
  return path
end

local function rewrite(target, is_image)
  local path, fragment = target:match("^([^#]*)(#?.*)$")
  path = repo_path(path)
  local sibling = path:match("^" .. EXAMPLES .. "/_([%w_.]+)/README%.md$")
  if sibling then
    return sibling .. ".html" .. fragment
  end
  if is_image then
    return RAW .. "/main/" .. path
  end
  local leaf = pandoc.path.filename(path)
  local kind = (path:match("/$") or not leaf:match("%.")) and "tree" or "blob"
  return REPO .. "/" .. kind .. "/main/" .. path:gsub("/$", "") .. fragment
end

function Link(el)
  if is_relative(el.target) then
    el.target = rewrite(el.target, false)
    return el
  end
end

-- The README's upstream marker: an HTML comment near the top of the file
-- (`<!-- upstream: [GOAD](https://...) -->`, invisible on GitHub) carries
-- the example's upstream as a markdown link, so the data lives with the
-- example rather than in this filter. dmz-pivot is original and carries no
-- marker.
local function upstream_marker(doc)
  for _, block in ipairs(doc.blocks) do
    if block.t == "RawBlock" and block.format:match("html") then
      local marker = block.text:match("<!%-%-%s*upstream:%s*(.-)%s*%-%->")
      if marker then
        return marker
      end
    end
  end
  return nil
end

-- Insert a Source row (the example's true package location in the
-- repository) and, when the README carries an upstream marker, an Upstream
-- row, as a borderless two-column table directly under the page title
-- (after the first h1 when it is still present; the title promotion may
-- have already lifted it out).
function Pandoc(doc)
  local path = EXAMPLES .. "/" .. dir
  local md = "|  |  |\n|----|----|\n"
      .. "| Source: | [`" .. path .. "`](" .. REPO .. "/tree/main/" .. path .. ") |\n"
  local upstream = upstream_marker(doc)
  if upstream then
    md = md .. "| Upstream: | " .. upstream .. " |\n"
  end
  local tbl = pandoc.read(md, "markdown").blocks[1]
  -- the house borderless idiom (`: {.borderless tbl-colwidths=[...]}`),
  -- applied directly to the table's attributes and column widths so the
  -- label column hugs regardless of where this filter runs in the chain
  tbl.attr = pandoc.Attr("", { "borderless" }, { ["tbl-colwidths"] = "[14,86]" })
  tbl.colspecs = { { pandoc.AlignDefault, 0.14 }, { pandoc.AlignDefault, 0.86 } }
  local pos = 1
  for i, block in ipairs(doc.blocks) do
    if block.t == "Header" and block.level == 1 then
      pos = i + 1
      break
    end
  end
  table.insert(doc.blocks, pos, tbl)
  return doc
end

function Image(el)
  if is_relative(el.src) then
    el.src = rewrite(el.src, true)
    return el
  end
end
