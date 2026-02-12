TODO: share highlights.scm with Zed

Requirements:

- nvim-treesitter
- nvim-lspconfig (optional, for LSP)

Lazy plugin:

```lua
{
    "kaspanet/silverscript",
    dependencies = { "nvim-treesitter/nvim-treesitter" },
    init = function(plugin)
        vim.opt.rtp:append(plugin.dir .. "/extensions/silverscript.nvim")
    end,
    config = function()
        require("silverscript").setup({
            lsp = {
                cmd = { "silverscript-lsp" },
                filetypes = { "silverscript" },
            },
        })
    end,
}
```

- After install, run :TSInstall silverscript (or add it to ensure_installed) so Tree‑sitter builds the parser.
