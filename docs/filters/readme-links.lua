-- Rewrite relative links on the symlinked example README pages.
--
-- Each page under docs/examples/ is a symlink to examples/<name>/README.md,
-- so relative links that resolve naturally on GitHub (notes.md, range.yaml,
-- recipes/) point at nothing in the rendered site. This filter rewrites them
-- to the repository: blob URLs for files, tree URLs for directories, raw
-- URLs for images. A link that resolves to another example's README stays
-- in-site as that example's doc page.

local REPO = "https://github.com/meridianlabs-ai/inspect_ranges"
local RAW = "https://raw.githubusercontent.com/meridianlabs-ai/inspect_ranges"

local function example_name()
  local input = (quarto and quarto.doc and quarto.doc.input_file)
      or PANDOC_STATE.input_files[1]
  return pandoc.path.filename(input):gsub("%.md$", "")
end

local name = example_name()

local function is_relative(target)
  return not (target:match("^%a[%w+.%-]*:") or target:match("^#") or target:match("^/"))
end

-- Resolve a link target against the README's true repo location,
-- collapsing any ../ segments.
local function repo_path(target)
  local path = "examples/" .. name .. "/" .. target:gsub("^%./", "")
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
  local sibling = path:match("^examples/([%w_.%-]+)/README%.md$")
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

-- Insert a "Source: examples/<name>" line pointing at the repository
-- directory, directly under the page title (after the first h1 when it is
-- still present; the title promotion may have already lifted it out).
function Pandoc(doc)
  local para = pandoc.Para({
    pandoc.Str("Source:"),
    pandoc.Space(),
    pandoc.Link(
      { pandoc.Code("examples/" .. name) },
      REPO .. "/tree/main/examples/" .. name
    ),
  })
  local pos = 1
  for i, block in ipairs(doc.blocks) do
    if block.t == "Header" and block.level == 1 then
      pos = i + 1
      break
    end
  end
  table.insert(doc.blocks, pos, para)
  return doc
end

function Image(el)
  if is_relative(el.src) then
    el.src = rewrite(el.src, true)
    return el
  end
end
