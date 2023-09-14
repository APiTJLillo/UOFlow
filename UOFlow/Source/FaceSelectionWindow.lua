----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------
FaceSelectionWindow = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

FaceSelectionWindow.TID = { OK=1006044, Cancel=1006045,  SelectAFace=1079788}
FaceSelectionWindow.faceStyles = {}
FaceSelectionWindow.faceStyle = nil

-- TO DO: GET FACE INDEX!!
FaceSelectionWindow.FaceIndex = 1
FaceSelectionWindow.maxFaceTypes = nil
FaceSelectionWindow.paperdollWindowWasShown = false 
FaceSelectionWindow.paperdollId = nil
FaceSelectionWindow.paperdollWindowName = nil

FaceSelectionWindow_GumpData = {}
local ActualFaceIndex = 1  -- what the player currently has set, if they cancel it will be set to this

FaceSelectionWindow.HUMAN = 1
FaceSelectionWindow.ELF = 2
FaceSelectionWindow.GARGOYLE = 3

local WindowName
----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function FaceSelectionWindow.Initialize()

	UO_GenericGump.retrieveWindowData (FaceSelectionWindow_GumpData)

	WindowName = FaceSelectionWindow_GumpData.windowName

	local race = WindowData.PlayerStatus.Race
	if(race == FaceSelectionWindow.GARGOYLE) then
		UOBuildTableFromCSV ("Data/GameData/gargoylefacestyles.csv", "FacesCSV")
	else
		UOBuildTableFromCSV ("Data/GameData/characterfacestyles.csv", "FacesCSV")
	end
	FaceSelectionWindow.faceStyles = FaceSelectionWindow.createWearableTable(WindowData.FacesCSV)
	-- What is this faceStyle used for? In this case, it is TileArtId column, later it becomes id column???
	FaceSelectionWindow.faceStyle  = WindowData.FacesCSV[1].TileArtId
	
	
	FaceSelectionWindow.maxFaceTypes = table.getn (FaceSelectionWindow.faceStyles)
	--Debug.PrintToDebugConsole(L"FaceSelectionWindow.Initialize: maxFaceTypes = "..StringToWString(tostring(FaceSelectionWindow.maxFaceTypes)))

	-- Get current face and convert to row index.
	local currentFaceType = GumpManagerGetPlayerFaceType()
	--Debug.Print("Face Type: "..currentFaceType)
	if currentFaceType ~= 0 then
		FaceSelectionWindow.FaceIndex = CSVUtilities.getRowIdWithColumnValue(WindowData.FacesCSV, "TileArtId", currentFaceType)
		ActualFaceIndex = FaceSelectionWindow.FaceIndex
	end
	--Debug.Print("Face Index: "..FaceSelectionWindow.FaceIndex)
	
	FaceSelectionWindow.UpdateFaceLabel()
	WindowUtils.SetWindowTitle(WindowName,  GetStringFromTid(FaceSelectionWindow.TID.SelectAFace))
	ButtonSetText(WindowName.."OKButton", GetStringFromTid(FaceSelectionWindow.TID.OK))
	ButtonSetText(WindowName.."CancelButton", GetStringFromTid(FaceSelectionWindow.TID.Cancel))

	FaceSelectionWindow.paperdollId = WindowData.PlayerStatus.PlayerId
	FaceSelectionWindow.paperdollWindowName = "PaperdollWindow"..FaceSelectionWindow.paperdollId
	
	if ( not(DoesWindowNameExist(FaceSelectionWindow.paperdollWindowName)) ) then
		--Debug.PrintToDebugConsole(L"FaceSelectionWindow.Initialize: paperdoll window not shown")
		Actions.TogglePaperdollWindow()
		FaceSelectionWindow.paperdollWindowWasShown = false
	else
		FaceSelectionWindow.paperdollWindowWasShown = true
		--Debug.PrintToDebugConsole(L"FaceSelectionWindow.Initialize: paperdoll window was shown")
	end
	
	Interface.OnCloseCallBack[WindowName] = FaceSelectionWindow.Cancel
	WindowSetShowing(WindowName, true)

end

function FaceSelectionWindow.Shutdown()
	UOUnloadCSVTable ("FacesCSV")
	FaceSelectionWindow.revertPaperdollWindowViewState()
end

function FaceSelectionWindow.ToggleFaceUp()

	--Debug.PrintToDebugConsole(L"FaceSelectionWindow.ToggleFaceUp: FaceSelectionWindow.FaceIndex = "..StringToWString(tostring(FaceSelectionWindow.FaceIndex)))

	if (FaceSelectionWindow.FaceIndex > (FaceSelectionWindow.maxFaceTypes  - 1)) then
		FaceSelectionWindow.FaceIndex = 1
	else
		FaceSelectionWindow.FaceIndex = FaceSelectionWindow.FaceIndex + 1
	end
		
	--Debug.Print("Face Index: "..FaceSelectionWindow.FaceIndex)
	GumpManagerSetPlayerFaceType(WindowData.FacesCSV[FaceSelectionWindow.FaceIndex].TileArtId)
	Debug.Print("Face Tileart ID"..WindowData.FacesCSV[FaceSelectionWindow.FaceIndex].TileArtId)
	FaceSelectionWindow.UpdateFaceLabel()
end
 
-- TO DO: Update paperdoll face!
function FaceSelectionWindow.ToggleFaceDown()

	--Debug.PrintToDebugConsole(L"FaceSelectionWindow.ToggleFaceDown: FaceSelectionWindow.FaceIndex = "..StringToWString(tostring(FaceSelectionWindow.FaceIndex)))
	
	if (FaceSelectionWindow.FaceIndex > (1)) then
		FaceSelectionWindow.FaceIndex = FaceSelectionWindow.FaceIndex - 1
	else
		FaceSelectionWindow.FaceIndex = FaceSelectionWindow.maxFaceTypes 
	end 


	GumpManagerSetPlayerFaceType(WindowData.FacesCSV[FaceSelectionWindow.FaceIndex].TileArtId)
	FaceSelectionWindow.UpdateFaceLabel()
end

function FaceSelectionWindow.UpdateFaceLabel()
	temp1 = FaceSelectionWindow.FaceIndex
	-- CJT - this is busted
	temp2 = FaceSelectionWindow.faceStyles[temp1].tid
	
	LabelSetText (WindowName.."FaceStyle", GetStringFromTid(FaceSelectionWindow.faceStyles[FaceSelectionWindow.FaceIndex].tid))
end

-- TO DO: Save face selection!
function FaceSelectionWindow.OK()
	WindowSetShowing(WindowName, false)
	FaceSelectionWindow.revertPaperdollWindowViewState()
	UO_GenericGump.broadcastButtonPress( WindowData.FacesCSV[FaceSelectionWindow.FaceIndex].TileArtId, FaceSelectionWindow_GumpData )
	
end

-- TO DO: Revert to player's original face selection!
function FaceSelectionWindow.Cancel()
	WindowSetShowing(WindowName, false)
	GumpManagerSetPlayerFaceType(WindowData.FacesCSV[ActualFaceIndex].TileArtId)

	FaceSelectionWindow.revertPaperdollWindowViewState()
	UO_GenericGump.broadcastButtonPress( 0, FaceSelectionWindow_GumpData )

end

-- Convenience function copied from CC to create Lua table from CSV files
function FaceSelectionWindow.createWearableTable(CSVTable)
	local wearableTable = {}
	local numWearables =  table.getn(CSVTable)

	--Debug.PrintToDebugConsole(L"FaceSelectionWindow.createWearableTable: numWearables = "..StringToWString(tostring(numWearables)))

	for i = 1,numWearables do
		-- HACKY IF STATEMENT CHECK BECAUSE CSV TABLE SEEMS TO CONTAIN NIL VALUES
		if not ((CSVTable[i].TileArtId == 0) and (CSVTable[i].StringId == 0))  then
			--Debug.PrintToDebugConsole(L"FaceSelectionWindow.createWearableTable: i = "..StringToWString(tostring(i)))
			--Debug.PrintToDebugConsole(L"FaceSelectionWindow.createWearableTable: CSVTable[i].Entitlement = "..StringToWString(tostring(CSVTable[i].Entitlement)))
			--Debug.PrintToDebugConsole(L"FaceSelectionWindow.createWearableTable: HasEntitlement(tonumber(CSVTable[i].Entitlement)) = "..StringToWString(tostring(HasEntitlement(tonumber(CSVTable[i].Entitlement)))))

			if ( ((CSVTable[i].Entitlement) and HasEntitlement(tonumber(CSVTable[i].Entitlement))) or
				(not(CSVTable[i].Entitlement)) ) then
					wearableTable[i] = {id=CSVTable[i].TileArtId, tid=CSVTable[i].StringId}
			else
				--Debug.PrintToDebugConsole(L"FaceSelectionWindow.createWearableTable: wearableTable[i] = nil ")
				wearableTable[i] = nil
			end
		end
	end
	
	return wearableTable
end

-- Convenience method to show or hide PD window based on its view state when FaceSelctionWindow was initialized
function FaceSelectionWindow.revertPaperdollWindowViewState() 
	if (not(FaceSelectionWindow.paperdollWindowWasShown)) then
		Actions.TogglePaperdollWindow()
	end
end