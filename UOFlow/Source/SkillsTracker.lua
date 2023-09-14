----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

SkillsTracker = { }
SkillsTracker.Created = false
SkillsTracker.Init = false
SkillsTracker.ShowAllMySkills = true

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

local createdSkillTrackers = {}

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function SkillsTracker.Initialize()
	SkillsTracker.ShowAllMySkills = Interface.LoadBoolean( "TrackerShowAllMySkills", SkillsTracker.ShowAllMySkills  )
	WindowRegisterEventHandler( this, WindowData.SkillDynamicData.Event, "SkillsTracker.UpdateSkill")
	
	WindowUtils.RestoreWindowPosition("SkillsTrackerWindow")
	
	LabelSetText("SkillsTrackerWindowInfoText", GetStringFromTid(1111939))
	
	SkillsTracker.Update()
	
	SkillsWindow.UpdateSkillsTrackerToggleButtonText()
end

function SkillsTracker.Shutdown()
	createdSkillTrackers = {}
	
	WindowUnregisterEventHandler(this, WindowData.SkillDynamicData.Event)
	
	WindowUtils.SaveWindowPosition("SkillsTrackerWindow")
end

function SkillsTracker.Context()
	if (SkillsTracker.ShowAllMySkills) then
		ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1154801),0,"custom",2,false)
	else
		ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1154802),0,"all",2,false)
	end
	ContextMenu.CreateLuaContextMenuItemWithString(GetStringFromTid(1015002),0,"refresh",2,false)
	ContextMenu.ActivateLuaContextMenu(SkillsTracker.ContextMenuCallback)
end

function SkillsTracker.ContextMenuCallback( returnCode, param )	
	if ( returnCode=="custom" ) then
		Interface.SaveBoolean( "TrackerShowAllMySkills", false )
		SkillsTracker.ShowAllMySkills = false
	elseif ( returnCode=="all" ) then
		Interface.SaveBoolean( "TrackerShowAllMySkills", true )
		SkillsTracker.ShowAllMySkills = true
	end
	SkillsTracker.Update()
end

function SkillsTracker.Update()
	SkillsTracker.Init = true
	-- Destroy the existing skill trackers
	for i=1, table.getn(createdSkillTrackers) do
		local serverId = createdSkillTrackers[i]
		local skillWindowName = "SkillsTrackerSkill"..serverId
		
		DestroyWindow(skillWindowName)
	end
	createdSkillTrackers = {}
	
	local numCustomSkills = 0

	if (SkillsTracker.ShowAllMySkills) then
		
		local lastSkillID = 0
		local template = "SkillsTrackerSkillTemplate"		
				
		for i=1,58 do
		
			local serverId = WindowData.SkillsCSV[i].ServerId
			
			local skillLevel = 0
			if(SkillsWindow.SkillDataMode == 0) then
				skillLevel = WindowData.SkillDynamicData[serverId].RealSkillValue
			else
				skillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue
			end
			
			if (skillLevel > 0) then
				
				numCustomSkills = numCustomSkills + 1
				local skillWindowName = "SkillsTrackerSkill"..serverId
				
				CreateWindowFromTemplate( skillWindowName, template, "SkillsTrackerWindow" )
				
				createdSkillTrackers[numCustomSkills] = serverId
				
				-- reanchor window
				WindowClearAnchors(skillWindowName)
				if (numCustomSkills==1) then
         			WindowAddAnchor( skillWindowName, "bottomright", "SkillsTrackerWindowDragHandle", "topright", 0, 3)
				else
        			WindowAddAnchor( skillWindowName, "bottomright", "SkillsTrackerSkill"..lastSkillID, "topright", 0, 3)
				end
			
				local displayName = GetStringFromTid(WindowData.SkillsCSV[i].NameTid)	
				LabelSetText(skillWindowName.."Name", displayName)
				
				SkillsTracker.UpdateSkill(serverId, i)
				lastSkillID = serverId
			end
		end
		
		
		local TotalPoints = 720
		
		local SkillPointsUsed = 0
		for i=0,57 do
			SkillPointsUsed = SkillPointsUsed + WindowData.SkillDynamicData[i].RealSkillValue
		end
		
		if SkillPointsUsed == 0 then
			if DoesWindowNameExist("SkillsTrackerWindow") then
				DestroyWindow("SkillsTrackerWindow")
			end
			return
		end
		
		local RemainingPoints = (TotalPoints * 10) - SkillPointsUsed

		if (RemainingPoints > 0 ) then
			RemainingPoints = tostring(RemainingPoints)
		else
			RemainingPoints = "0"
		end
		
		local dot = 0

		if (string.len(RemainingPoints) > 1 ) then
			dot = string.sub(RemainingPoints, string.len(RemainingPoints), string.len(RemainingPoints))
			RemainingPoints =string.sub(RemainingPoints, 1, string.len(RemainingPoints) - 1) .. "." .. dot .. "%"
		else
			RemainingPoints = "0." .. RemainingPoints ..  "%"
		end

		numCustomSkills = numCustomSkills + 2
		createdSkillTrackers[numCustomSkills-1] = 15000
		local skillWindowName = "SkillsTrackerSkill"..15000
		CreateWindowFromTemplate( skillWindowName, template, "SkillsTrackerWindow" )
		WindowAddAnchor( skillWindowName, "bottomright", "SkillsTrackerSkill"..lastSkillID, "topright", 0, 3)
		DestroyWindow(skillWindowName.."Value")
		WindowSetDimensions(skillWindowName.."Name", 320, 16)
		LabelSetText(skillWindowName.."Name", L"----------------------------------------------------------------")
		
		createdSkillTrackers[numCustomSkills] = 15001
		local skillWindowName = "SkillsTrackerSkill"..15001
		CreateWindowFromTemplate( skillWindowName, template, "SkillsTrackerWindow" )
		WindowAddAnchor( skillWindowName, "bottomright", "SkillsTrackerSkill"..15000, "topright", 0, 3)
		DestroyWindow(skillWindowName.."Value")
		WindowSetDimensions(skillWindowName.."Name", 320, 16)
		LabelSetTextAlign(skillWindowName.."Name", "right")
		local skillFormatted = StringToWString(RemainingPoints)
		LabelSetText(skillWindowName.."Name", ReplaceTokens(GetStringFromTid(1154803), {skillFormatted}))
	else
		-- Create new skill trackers
		local customSkills = SystemData.Settings.Interface.CustomSkills
		numCustomSkills = table.getn(customSkills)
		
			
		for i=1,numCustomSkills do
			local skillId = customSkills[i]
			local serverId = WindowData.SkillsCSV[skillId].ServerId
		
			local skillWindowName = "SkillsTrackerSkill"..serverId
			CreateWindowFromTemplate( skillWindowName, "SkillsTrackerSkillTemplate", "SkillsTrackerWindow" )
			
			createdSkillTrackers[i] = serverId
			
			-- reanchor window
			WindowClearAnchors(skillWindowName)
			if (i==1) then
         		WindowAddAnchor( skillWindowName, "bottomright", "SkillsTrackerWindowDragHandle", "topright", 0, 3)
			else
				local previousId = WindowData.SkillsCSV[customSkills[i-1]].ServerId
        		WindowAddAnchor( skillWindowName, "bottomright", "SkillsTrackerSkill"..previousId, "topright", 0, 3)
			end
		
			local displayName = GetStringFromTid(WindowData.SkillsCSV[skillId].NameTid)	
			LabelSetText(skillWindowName.."Name", displayName)
			
			SkillsTracker.UpdateSkill(serverId)
		end
	end
	
	
	if (numCustomSkills == 0) then
		WindowSetShowing("SkillsTrackerWindowInfoText", true)
	else
		WindowSetShowing("SkillsTrackerWindowInfoText", false)
	end
	SkillsTracker.Created = true
end

function SkillsTracker.UpdateSkill(index, skillId)
	local serverId = index
	if(serverId == nil) then
		serverId = WindowData.UpdateInstanceId
	end
	if (serverId == 15000 or serverId == 15001) then
	
	else
		local skillWindowName = "SkillsTrackerSkill"..serverId
		
		if( not DoesWindowNameExist(skillWindowName) ) then
			return
		end
		
		local skillLevel = nil
		if (SkillsWindow.SkillDataMode == 0) then
			skillLevel = WindowData.SkillDynamicData[serverId].RealSkillValue
		else
			skillLevel = WindowData.SkillDynamicData[serverId].TempSkillValue
		end
		local skillLevelCap = WindowData.SkillDynamicData[serverId].SkillCap
		
		if (SkillsWindow.SkillTargetVals[skillId]) then
			skillLevelCap = SkillsWindow.SkillTargetVals[skillId]
		end
		
		-- Clean up the number so it works as a percentage
		local skillFormatted = SkillsWindow.FormatSkillValue(skillLevel)
		
		if (SkillsWindow.SkillCapMode == 0) then
			if skillLevel ~= nil then
				LabelSetText(skillWindowName.."Value", skillFormatted..L"%")
			else
				-- This shouldn't happen unless it misregisters the skills
				LabelSetText(skillWindowName.."Value", L"---.-%")
			end	
		else	
			-- want to show skill caps	
			local capFormatted = SkillsWindow.FormatSkillValue(skillLevelCap)
			if skillLevel ~= nil then
				LabelSetText(skillWindowName.."Value", skillFormatted..L"/"..capFormatted..L"%")
			else
				-- This shouldn't happen unless it misregisters the skills
				LabelSetText(skillWindowName.."Value", L"---.-/---.-%")
			end
		end		

		if (SkillsTracker.Created and DoesWindowNameExist("SkillsTrackerSkill15001Value")) then
	
			local skillWindowName = "SkillsTrackerSkill"..15001

			
			local TotalPoints = 720
			
			local SkillPointsUsed = 0
			for i=0,57 do
				SkillPointsUsed = SkillPointsUsed + WindowData.SkillDynamicData[i].RealSkillValue
			end
			
			local RemainingPoints = (TotalPoints * 10) - SkillPointsUsed

			if (RemainingPoints > 0 ) then
				RemainingPoints = tostring(RemainingPoints)
			else
				RemainingPoints = "0"
			end
			
			local dot = 0

			if (string.len(RemainingPoints) > 1 ) then
				dot = string.sub(RemainingPoints, string.len(RemainingPoints), string.len(RemainingPoints))
				RemainingPoints =string.sub(RemainingPoints, 1, string.len(RemainingPoints) - 1) .. "." .. dot .. "%"
			else
				RemainingPoints = "0." .. RemainingPoints .. "%"
			end

			local skillFormatted = StringToWString(RemainingPoints)

			LabelSetText(skillWindowName.."Value", skillFormatted)
		end
	end
end