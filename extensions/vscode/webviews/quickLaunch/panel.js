(function () {
  const modelElement = document.getElementById("quick-launch-model");
  const stateElement = document.getElementById("quick-launch-state");
  const ctorFields = document.getElementById("constructor-fields");
  const argFields = document.getElementById("arg-fields");
  const functionSelect = document.getElementById("function-select");
  const loadButton = document.getElementById("load-button");

  if (
    !modelElement ||
    !stateElement ||
    !ctorFields ||
    !argFields ||
    !functionSelect ||
    !loadButton
  ) {
    throw new Error("Quick launch panel failed to initialize.");
  }

  const vscode = acquireVsCodeApi();
  const model = JSON.parse(modelElement.textContent || "null");
  const state = JSON.parse(stateElement.textContent || "null");

  state.identityLabels =
    state.identityLabels && typeof state.identityLabels === "object"
      ? state.identityLabels
      : {};
  state.savedCountsByFunction =
    state.savedCountsByFunction &&
    typeof state.savedCountsByFunction === "object"
      ? state.savedCountsByFunction
      : {};
  state.savedTotalCount = Number(state.savedTotalCount) || 0;

  function fieldValue(defaultValue) {
    return typeof defaultValue === "string"
      ? defaultValue
      : String(defaultValue ?? "");
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function normalizedType(typeName) {
    return String(typeName ?? "").trim().toLowerCase();
  }

  function helperSlot(param) {
    const typeName = normalizedType(param.type);
    const name = String(param.name ?? "").toLowerCase();
    if (typeName === "pubkey") {
      return "pubkey";
    }
    if (typeName === "sig") {
      return "secret";
    }
    if (
      (typeName === "bytes32" ||
        typeName === "byte[32]" ||
        typeName === "bytes") &&
      name.includes("pkh")
    ) {
      return "pkh";
    }
    return null;
  }

  function tokenFor(alias, slot) {
    return alias + "." + slot;
  }

  function canonicalIdentityToken(raw) {
    const trimmed = String(raw ?? "").trim();
    const match =
      /^(?:keypair|identity)([1-9][0-9]*)(?:[.](pubkey|secret|pkh))?$/.exec(
        trimmed,
      );
    if (!match) {
      return null;
    }
    const index = match[1];
    const slot = match[2];
    return slot ? "keypair" + index + "." + slot : "keypair" + index;
  }

  function displayLabelFor(alias) {
    const label = state.identityLabels[alias];
    return typeof label === "string" && label.trim()
      ? label.trim()
      : alias;
  }

  function syncAliasesFromFields() {
    state.constructorArgs = collectFields(ctorFields, "constructor");
    syncCurrentArgState();

    const found = new Map();
    const consider = (raw) => {
      const canonical = canonicalIdentityToken(raw);
      if (!canonical) {
        return;
      }
      const index = Number(canonical.slice("keypair".length).split(".")[0]);
      if (!found.has(index)) {
        found.set(index, "keypair" + index);
      }
    };

    state.keyAliases.forEach(consider);
    Object.values(state.constructorArgs).forEach(consider);
    Object.values(state.argsByFunction).forEach((args) => {
      Object.values(args).forEach(consider);
    });

    state.keyAliases = [...found.entries()]
      .sort((left, right) => left[0] - right[0])
      .map((entry) => entry[1]);
    state.identityLabels = Object.fromEntries(
      state.keyAliases
        .map((alias) => [alias, state.identityLabels[alias]])
        .filter(
          ([alias, label]) =>
            typeof label === "string" &&
            label.trim() &&
            label.trim() !== alias,
        )
        .map(([alias, label]) => [alias, label.trim()]),
    );
  }

  function nextAlias() {
    syncAliasesFromFields();
    let max = 0;
    state.keyAliases.forEach((alias) => {
      const match = /^keypair([0-9]+)$/.exec(String(alias).trim());
      if (match) {
        max = Math.max(max, Number(match[1]));
      }
    });
    return "keypair" + (max + 1);
  }

  function fillFieldWithToken(input, slot, alias) {
    input.value = tokenFor(alias, slot);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.focus();
  }

  function addAlias(fillInput, fillSlot) {
    syncAliasesFromFields();
    const alias = nextAlias();
    state.keyAliases.push(alias);
    syncAliasesFromFields();
    if (fillInput && fillSlot) {
      fillFieldWithToken(fillInput, fillSlot, alias);
    }
    return alias;
  }

  function renderFields(container, params, values, group) {
    if (!params.length) {
      container.innerHTML = '<p class="empty">No parameters</p>';
      return;
    }

    container.innerHTML = params
      .map((param) => {
        const value = fieldValue(values[param.name]);
        const helper = helperSlot(param);
        const escapedValue = escapeHtml(value);
        return (
          '<label>' +
          param.name +
          '<span class="meta">' +
          param.type +
          "</span>" +
          (helper ? '<span class="badge">key</span>' : "") +
          "</label>" +
          '<div class="field-row">' +
          '<input data-group="' +
          group +
          '" data-name="' +
          param.name +
          '" value="' +
          escapedValue +
          '" placeholder="' +
          param.type +
          '"' +
          (helper
            ? ' class="crypto-input" data-helper-slot="' + helper + '"'
            : "") +
          " />" +
          (helper
            ? '<button type="button" class="secondary-button field-action key-button" data-helper-slot="' +
              helper +
              '" data-field-name="' +
              param.name +
              '">Pick</button>'
            : "") +
          "</div>"
        );
      })
      .join("");
  }

  function currentEntrypoint() {
    return (
      model.entrypoints.find((entry) => entry.name === functionSelect.value) ||
      model.entrypoints[0]
    );
  }

  function ensureArgState(functionName) {
    if (!state.argsByFunction[functionName]) {
      state.argsByFunction[functionName] = {};
    }
    return state.argsByFunction[functionName];
  }

  function collectFields(container, group) {
    const out = {};
    container
      .querySelectorAll('input[data-group="' + group + '"]')
      .forEach((input) => {
        out[input.dataset.name] =
          canonicalIdentityToken(input.value) ?? input.value;
      });
    return out;
  }

  function syncCurrentArgState() {
    const entrypoint = currentEntrypoint();
    if (!entrypoint) {
      return;
    }
    state.argsByFunction[entrypoint.name] = collectFields(argFields, "args");
  }

  function currentForm() {
    syncAliasesFromFields();
    state.function = functionSelect.value;
    return {
      function: state.function,
      constructorArgs: state.constructorArgs,
      argsByFunction: state.argsByFunction,
      keyAliases: state.keyAliases,
      identityLabels: state.identityLabels,
    };
  }

  function renderFunctionOptions() {
    functionSelect.innerHTML = model.entrypoints
      .map((entry) => {
        const signature = entry.params
          .map((param) => param.type + " " + param.name)
          .join(", ");
        const selected = entry.name === state.function ? " selected" : "";
        return (
          '<option value="' +
          entry.name +
          '"' +
          selected +
          ">" +
          entry.name +
          "(" +
          signature +
          ")" +
          "</option>"
        );
      })
      .join("");
  }

  function renderArgs() {
    const entrypoint = currentEntrypoint();
    if (!entrypoint) {
      argFields.innerHTML = '<p class="empty">No entrypoints</p>';
      return;
    }
    renderFields(
      argFields,
      entrypoint.params,
      ensureArgState(entrypoint.name),
      "args",
    );
  }

  function renderLoadButton() {
    const functionName = String(functionSelect.value || state.function || "");
    const currentCount = Number(state.savedCountsByFunction[functionName] ?? 0);
    loadButton.textContent =
      currentCount > 0 ? "Load (" + currentCount + ")" : "Load";

    if (state.savedTotalCount === 0) {
      loadButton.title = "No saved scenarios for this contract yet.";
      return;
    }

    if (functionName && currentCount !== state.savedTotalCount) {
      loadButton.title =
        currentCount > 0
          ? currentCount +
            " saved for " +
            functionName +
            ", " +
            state.savedTotalCount +
            " total for this contract."
          : "No saved scenarios for " +
            functionName +
            ". " +
            state.savedTotalCount +
            " saved for this contract.";
      return;
    }

    loadButton.title = state.savedTotalCount + " saved for this contract.";
  }

  function renderAllFields() {
    renderFields(
      ctorFields,
      model.constructorParams,
      state.constructorArgs,
      "constructor",
    );
    renderArgs();
  }

  function closeDropdowns() {
    document
      .querySelectorAll(".identity-dropdown")
      .forEach((node) => node.remove());
  }

  function clearAliasTokens(alias) {
    const tokens = new Set(
      ["pubkey", "secret", "pkh"].map((slot) => tokenFor(alias, slot)),
    );
    const clearValues = (values) =>
      Object.fromEntries(
        Object.entries(values).map(([name, raw]) => {
          const canonical = canonicalIdentityToken(raw);
          return [name, canonical && tokens.has(canonical) ? "" : raw];
        }),
      );

    state.constructorArgs = clearValues(state.constructorArgs);
    state.argsByFunction = Object.fromEntries(
      Object.entries(state.argsByFunction).map(([name, values]) => [
        name,
        clearValues(values),
      ]),
    );
  }

  function deleteAlias(alias) {
    state.keyAliases = state.keyAliases.filter((entry) => entry !== alias);
    delete state.identityLabels[alias];
    clearAliasTokens(alias);
    renderAllFields();
    closeDropdowns();
  }

  function showDropdown(input, slot) {
    syncAliasesFromFields();
    const fieldRow = input.closest(".field-row");
    if (!fieldRow) {
      return;
    }
    closeDropdowns();

    const dropdown = document.createElement("div");
    dropdown.className = "identity-dropdown";

    state.keyAliases.forEach((alias) => {
      const item = document.createElement("div");
      item.className = "identity-choice";
      const main = document.createElement("div");
      main.className = "identity-choice-main";
      const name = document.createElement("span");
      name.className = "identity-choice-name";
      name.textContent = displayLabelFor(alias);
      const value = document.createElement("span");
      value.className = "identity-choice-value";
      value.textContent = tokenFor(alias, slot);
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "identity-choice-delete";
      remove.textContent = "X";
      remove.title = "Delete " + displayLabelFor(alias);
      remove.addEventListener("click", (event) => {
        event.stopPropagation();
        deleteAlias(alias);
      });
      main.append(name, value);
      item.append(main, remove);
      item.addEventListener("click", () => {
        fillFieldWithToken(input, slot, alias);
        closeDropdowns();
      });
      dropdown.appendChild(item);
    });

    if (state.keyAliases.length) {
      const divider = document.createElement("div");
      divider.className = "identity-divider";
      dropdown.appendChild(divider);
    }

    const add = document.createElement("div");
    add.className = "identity-choice";
    const next = nextAlias();
    const addName = document.createElement("span");
    addName.className = "identity-choice-name";
    addName.textContent = "Add " + next;
    const addValue = document.createElement("span");
    addValue.className = "identity-choice-value";
    addValue.textContent = tokenFor(next, slot);
    add.append(addName, addValue);
    add.addEventListener("click", () => {
      addAlias(input, slot);
      closeDropdowns();
    });
    dropdown.appendChild(add);

    fieldRow.appendChild(dropdown);
  }

  function send(kind) {
    vscode.postMessage({
      kind,
      form: currentForm(),
    });
  }

  functionSelect.addEventListener("change", () => {
    syncCurrentArgState();
    state.function = functionSelect.value;
    renderArgs();
    renderLoadButton();
    closeDropdowns();
  });

  renderFunctionOptions();
  renderAllFields();
  renderLoadButton();

  document.addEventListener("click", (event) => {
    const target =
      event.target instanceof Element
        ? event.target
        : event.target?.parentElement ?? null;
    if (!target) {
      return;
    }

    const button = target.closest(".key-button");
    if (button) {
      const row = button.closest(".field-row");
      const input = row?.querySelector("input.crypto-input");
      const slot = button.dataset.helperSlot;
      if (input && slot) {
        event.stopPropagation();
        showDropdown(input, slot);
      }
      return;
    }

    const input = target.closest("input.crypto-input");
    if (input && input.dataset.helperSlot) {
      event.stopPropagation();
      showDropdown(input, input.dataset.helperSlot);
      return;
    }

    if (!target.closest(".identity-dropdown")) {
      closeDropdowns();
    }
  });

  document
    .getElementById("load-button")
    .addEventListener("click", () => send("loadSaved"));
  document
    .getElementById("save-button")
    .addEventListener("click", () => send("saveSaved"));
  document
    .getElementById("run-button")
    .addEventListener("click", () => send("run"));
  document
    .getElementById("debug-button")
    .addEventListener("click", () => send("debug"));

  window.addEventListener("message", (event) => {
    const message = event.data;
    if (!message || typeof message !== "object") {
      return;
    }
    if (
      message.kind === "triggerLaunch" &&
      (message.launchKind === "run" || message.launchKind === "debug")
    ) {
      send(message.launchKind);
    }
  });
})();
