local M = {}

function M.setup()
    vim.filetype.add({ extension = { sil = "silverscript" } })

    local parser_config = require("nvim-treesitter.parsers").get_parser_configs()

    -- For actual deployment
    parser_config.silverscript = {
        install_info = {
            url = "https://github.com/kaspanet/silverscript",
            files = { "src/parser.c" },
            branch = "main",
            location = 'tree-sitter',
        },
        filetype = "silverscript",
    }

    -- Dev mode only
    -- parser_config.silverscript = {
    --     install_info = {
    --         url = "/mnt/d/Dev/kaspa/silverscript",
    --         location = "tree-sitter",
    --         files = { "src/parser.c" },
    --     },
    --     filetype = "silverscript",
    -- }
end

return M
