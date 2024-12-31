-- Configuration window for Visual Programming blocks

if not VisualProgrammingInterface then
    VisualProgrammingInterface = {}
end

-- Initialize Config system immediately
VisualProgrammingInterface.Config = {
    currentBlock = nil,
    paramControls = {},
    initialized = true,
    
    Show = function(self, block)
        if not block then 
            Debug.Print("No block provided to configure")
            return 
        end
        
        Debug.Print("Showing config window for block: " .. (block.type or "unknown"))
        
        -- Ensure Actions system is initialized
        if not VisualProgrammingInterface.Actions then
            Debug.Print("Actions system not initialized")
            return
        end
        
        -- Get action definition
        local action = VisualProgrammingInterface.Actions:get(block.type)
        if not action then
            Debug.Print("Unknown action type: " .. tostring(block.type))
            return
        end
        
        -- Store current block
        self.currentBlock = block
        self.paramControls = {}
        
        -- Initialize block params if needed
        if not block.params then
            block.params = {}
        end
        
        -- Initialize default params from action definition
        if action.params then
            for _, param in ipairs(action.params) do
                if param.name and block.params[param.name] == nil then
                    block.params[param.name] = param.default
                end
            end
        end
        
        local dialogWindowName = "BlockConfigWindow"
        
        -- Destroy existing window to prevent UI conflicts
        if DoesWindowNameExist(dialogWindowName) then
            DestroyWindow(dialogWindowName)
        end

        -- Create window from template
        CreateWindowFromTemplate(dialogWindowName, "BlockConfigWindow", "Root")
        if not DoesWindowNameExist(dialogWindowName) then
            Debug.Print("Failed to create config window")
            return
        end
        
        -- Set window title
        LabelSetText(dialogWindowName .. "Chrome_UO_TitleBar_WindowTitle", StringToWString("Configure " .. tostring(block.type or "Block")))
        
        -- Get scroll window and create scroll child
        local scrollWindow = dialogWindowName.."ContentScrollWindow"
        local scrollChild = scrollWindow.."ScrollChild"
        
        -- Verify scroll window exists
        if not DoesWindowNameExist(scrollWindow) then
            Debug.Print("Scroll window not found: " .. scrollWindow)
            return
        end
        
        -- Initialize scroll window structure
        if not DoesWindowNameExist(scrollChild) then
            CreateWindow(scrollChild, false)
            WindowSetParent(scrollChild, scrollWindow)
            ScrollWindowSetScrollChild(scrollWindow, scrollChild)
        end
        
        -- Add block description at top of scroll content
        local descWindow = scrollChild.."_Description"
        CreateWindowFromTemplate(descWindow, "UO_Default_Label", scrollChild)
        WindowClearAnchors(descWindow)
        WindowAddAnchor(descWindow, "topleft", scrollChild, "topleft", 15, 10)
        WindowAddAnchor(descWindow, "topright", scrollChild, "topright", -15, 10)
        WindowSetLayer(descWindow, Window.Layers.DEFAULT)
        WindowSetTintColor(descWindow, 255, 234, 188)
        LabelSetText(descWindow, StringToWString(action.description or ""))
        
        -- Initialize offset for parameters
        local yOffset = 50
        
        -- Initialize params array if needed
        if not action.params then
            action.params = {}
        end
        
        for _, param in ipairs(action.params) do
            -- Skip invalid parameters
            if not param or not param.name or not param.type then
                Debug.Print("Invalid parameter definition found")
            else
                local paramWindow
                local currentValue = block.params[param.name] or param.default
                
                if param.type == "number" then
                    paramWindow = self:CreateNumberParam(scrollChild, param, currentValue, yOffset)
                elseif param.type == "select" then
                    paramWindow = self:CreateSelectParam(scrollChild, param, currentValue, yOffset)
                elseif param.type == "boolean" then
                    paramWindow = self:CreateBooleanParam(scrollChild, param, currentValue, yOffset)
                end
                
                if paramWindow then
                    yOffset = yOffset + 60 -- Increased spacing between parameters
                end
            end
        end
        
        -- Add trigger configuration options
        if block.type == "Trigger" then
            local triggerConfig = block.params.triggerConfig or { always = true, unique = false }
            block.params.triggerConfig = triggerConfig
            
            -- Create "Always" option
            local alwaysWindow = self:CreateBooleanParam(scrollChild, { name = "Always", type = "boolean" }, triggerConfig.always, yOffset)
            yOffset = yOffset + 60
            
            -- Create "Unique" option
            local uniqueWindow = self:CreateBooleanParam(scrollChild, { name = "Unique", type = "boolean" }, triggerConfig.unique, yOffset)
            yOffset = yOffset + 60
        end
        
        -- Update scroll window content size
        if yOffset > 0 then
            WindowSetDimensions(scrollChild, 360, yOffset)
            ScrollWindowUpdateScrollRect(scrollWindow)
        end
        
        WindowSetShowing(dialogWindowName, true)
    end,

    CreateNumberParam = function(self, parent, param, currentValue, yOffset)
        local paramWindow = parent .. param.name
        CreateWindow(paramWindow, true)
        WindowSetParent(paramWindow, parent)
        WindowSetDimensions(paramWindow, 340, 50)
        WindowSetLayer(paramWindow, Window.Layers.DEFAULT)
        WindowClearAnchors(paramWindow)
        WindowAddAnchor(paramWindow, "top", parent, "top", 0, yOffset)
        
        -- Create label
        local labelWindow = paramWindow .. "Label"
        CreateWindowFromTemplate(labelWindow, "UO_Default_Label", paramWindow)
        WindowSetDimensions(labelWindow, 180, 20)
        WindowClearAnchors(labelWindow)
        WindowAddAnchor(labelWindow, "left", paramWindow, "left", 10, 15)
        LabelSetText(labelWindow, StringToWString(param.name .. ":"))
        WindowSetTintColor(labelWindow, 255, 234, 188)
        
        -- Create textbox
        local inputWindow = paramWindow .. "Input"
        CreateWindowFromTemplate(inputWindow, "UO_Default_TextBox", paramWindow)
        WindowSetDimensions(inputWindow, 180, 32)
        WindowClearAnchors(inputWindow)
        WindowAddAnchor(inputWindow, "right", paramWindow, "right", -10, 10)
        TextBoxSetText(inputWindow, StringToWString(tostring(currentValue)))
        
        -- Add tooltip
        if param.validate then
            local tooltip = "Enter a valid number"
            if param.name == "time" then
                tooltip = "Enter a time in milliseconds (0-10000)"
            elseif param.name == "range" then
                tooltip = "Enter a range in tiles (1-20)"
            elseif param.name == "spellId" then
                tooltip = "Enter a valid spell ID (1-100)"
            end
            Tooltips.CreateTextOnlyTooltip(inputWindow, StringToWString(tooltip))
            Tooltips.Finalize()
            Tooltips.AnchorTooltip(Tooltips.ANCHOR_WINDOW_TOP)
        end
        
        table.insert(self.paramControls, {
            name = param.name,
            window = inputWindow,
            type = "number",
            validate = param.validate
        })
        
        return paramWindow
    end,

    CreateSelectParam = function(self, parent, param, currentValue, yOffset)
        local paramWindow = parent .. param.name
        CreateWindow(paramWindow, true)
        WindowSetParent(paramWindow, parent)
        WindowSetDimensions(paramWindow, 340, 50)
        WindowSetLayer(paramWindow, Window.Layers.DEFAULT)
        WindowClearAnchors(paramWindow)
        WindowAddAnchor(paramWindow, "top", parent, "top", 0, yOffset)
        
        -- Create label
        local labelWindow = paramWindow .. "Label"
        CreateWindowFromTemplate(labelWindow, "UO_Default_Label", paramWindow)
        WindowSetDimensions(labelWindow, 180, 20)
        WindowClearAnchors(labelWindow)
        WindowAddAnchor(labelWindow, "left", paramWindow, "left", 10, 15)
        LabelSetText(labelWindow, StringToWString(param.name .. ":"))
        WindowSetTintColor(labelWindow, 255, 234, 188)
        
        -- Create textbox for selection
        local inputWindow = paramWindow .. "Input"
        CreateWindowFromTemplate(inputWindow, "UO_Default_TextBox", paramWindow)
        WindowSetDimensions(inputWindow, 180, 32)
        WindowClearAnchors(inputWindow)
        WindowAddAnchor(inputWindow, "right", paramWindow, "right", -10, 10)
        
        -- Set current value or default
        if param.options then
            local value = currentValue
            if not value and #param.options > 0 then
                value = param.options[1]
            end
            TextBoxSetText(inputWindow, StringToWString(value or ""))
        else
            TextBoxSetText(inputWindow, L"No options available")
        end
        
        table.insert(self.paramControls, {
            name = param.name,
            window = inputWindow,
            type = "select",
            validate = param.validate
        })
        
        return paramWindow
    end,

    CreateBooleanParam = function(self, parent, param, currentValue, yOffset)
        local paramWindow = parent .. param.name
        CreateWindow(paramWindow, true)
        WindowSetParent(paramWindow, parent)
        WindowSetDimensions(paramWindow, 340, 50)
        WindowSetLayer(paramWindow, Window.Layers.DEFAULT)
        WindowClearAnchors(paramWindow)
        WindowAddAnchor(paramWindow, "top", parent, "top", 0, yOffset)
        
        -- Create label
        local labelWindow = paramWindow .. "Label"
        CreateWindowFromTemplate(labelWindow, "UO_Default_Label", paramWindow)
        WindowSetDimensions(labelWindow, 180, 20)
        WindowClearAnchors(labelWindow)
        WindowAddAnchor(labelWindow, "left", paramWindow, "left", 10, 15)
        LabelSetText(labelWindow, StringToWString(param.name .. ":"))
        WindowSetTintColor(labelWindow, 255, 234, 188)
        
        -- Create textbox for boolean
        local inputWindow = paramWindow .. "Input"
        CreateWindowFromTemplate(inputWindow, "UO_Default_TextBox", paramWindow)
        WindowSetDimensions(inputWindow, 180, 32)
        WindowClearAnchors(inputWindow)
        WindowAddAnchor(inputWindow, "right", paramWindow, "right", -10, 10)
        
        -- Set current value
        TextBoxSetText(inputWindow, StringToWString(currentValue and "True" or "False"))
        
        table.insert(self.paramControls, {
            name = param.name,
            window = inputWindow,
            type = "boolean",
            validate = param.validate
        })
        
        return paramWindow
    end,

    Hide = function(self)
        local dialogWindowName = "BlockConfigWindow"
        if DoesWindowNameExist(dialogWindowName) then
            DestroyWindow(dialogWindowName)
        end
        self.currentBlock = nil
        self.paramControls = {}
    end,

    Save = function(self)
        local block = self.currentBlock
        if not block then return end
        
        local action = VisualProgrammingInterface.Actions:get(block.type)
        if not action then return end
        
        local dialogWindowName = "BlockConfigWindow"
        
        -- Collect new parameter values
        local newParams = {}
        local hasErrors = false
        
        for _, control in ipairs(self.paramControls) do
            local value
            
            if control.type == "number" then
                local text = TextBoxGetText(control.window)
                if text then
                    value = tonumber(text)
                end
            elseif control.type == "select" then
                local text = TextBoxGetText(control.window)
                if text then
                    value = WStringToString(text)
                end
            elseif control.type == "boolean" then
                local text = TextBoxGetText(control.window)
                if text then
                    value = (WStringToString(text) == "True")
                end
            end
            
            -- Validate the value and show error feedback
            if not value or (control.validate and not control.validate(value)) then
                hasErrors = true
                
                -- Create or update error label
                local errorLabel = control.window .. "Error"
                if not DoesWindowNameExist(errorLabel) then
                    CreateWindowFromTemplate(errorLabel, "UO_Default_Label", control.window)
                    WindowClearAnchors(errorLabel)
                    WindowAddAnchor(errorLabel, "bottomright", control.window, "bottomright", 0, 20)
                    WindowSetLayer(errorLabel, Window.Layers.POPUP)
                end
                
                -- Show error message with red text
                LabelSetText(errorLabel, L"Invalid value")
                WindowSetTintColor(errorLabel, 255, 0, 0)
                WindowSetShowing(errorLabel, true)
                
                Debug.Print("Invalid value for parameter: " .. control.name)
                break
            else
                -- Hide error label if it exists
                local errorLabel = control.window .. "Error"
                if DoesWindowNameExist(errorLabel) then
                    WindowSetShowing(errorLabel, false)
                end
            end
            
            newParams[control.name] = value
        end
        
        -- Only update if all parameters are valid
        if not hasErrors then
            block.params = newParams
            block:updateVisuals()
            self:Hide()
        else
            -- Show error message at bottom of window
            local errorMsg = dialogWindowName.."_ErrorMsg"
            if not DoesWindowNameExist(errorMsg) then
                CreateWindowFromTemplate(errorMsg, "UO_Default_Label", dialogWindowName)
                WindowClearAnchors(errorMsg)
                WindowAddAnchor(errorMsg, "bottom", dialogWindowName, "bottom", 0, -40)
                WindowSetLayer(errorMsg, Window.Layers.POPUP)
            end
            LabelSetText(errorMsg, L"Please correct the invalid values")
            WindowSetTintColor(errorMsg, 255, 0, 0)
            WindowSetShowing(errorMsg, true)
        end
    end,

    Cancel = function(self)
        self:Hide()
    end
}

Debug.Print("Visual Programming Config system initialized")

-- Event handlers
function VisualProgrammingInterface.ConfigOKButton()
    VisualProgrammingInterface.Config:Save()
end

function VisualProgrammingInterface.ConfigCancelButton()
    VisualProgrammingInterface.Config:Cancel()
end
