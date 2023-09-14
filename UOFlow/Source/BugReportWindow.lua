----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

BugReportWindow = {}

BugReportWindow.NUM_MACROS = 12
BugReportWindow.NUM_MACRO_ICONS = 18
BugReportWindow.MACRO_ICONS_ID_BASE = 200

BugReportWindow.activeId = 1
BugReportWindow.iconNum = 0

BugReportWindow.bugTypes = {}
BugReportWindow.bugTypes.BUG_WORLD			= 1
BugReportWindow.bugTypes.BUG_WEARABLES		= 2
BugReportWindow.bugTypes.BUG_COMBAT			= 3
BugReportWindow.bugTypes.BUG_UI				= 4
BugReportWindow.bugTypes.BUG_CRASH			= 5
BugReportWindow.bugTypes.BUG_STUCK			= 6
BugReportWindow.bugTypes.BUG_ANIMATIONS		= 7
BugReportWindow.bugTypes.BUG_PERFORMANCE	= 8
BugReportWindow.bugTypes.BUG_NPCS			= 9
BugReportWindow.bugTypes.BUG_CREATURES		= 10
BugReportWindow.bugTypes.BUG_PETS			= 11
BugReportWindow.bugTypes.BUG_HOUSING		= 12
BugReportWindow.bugTypes.BUG_LOST_ITEM		= 13
BugReportWindow.bugTypes.BUG_EXPLOIT		= 14
BugReportWindow.bugTypes.BUG_OTHER			= 15

BugReportWindow.Size = 15
BugReportWindow.selectedType = BugReportWindow.bugTypes.BUG_OTHER
						
					--Bug Report, Submit, Clear, Select Bug Type, Please enter description of Bug, Your bug has been sent.
BugReportWindow.TID = {Bug = 1077790, Submit = 1077787, Clear = 3000154, Select = 1077788, Description = 1077789, Sent = 1077901}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

----------------------------------------------------------------
-- BugReportWindow Functions
----------------------------------------------------------------

-- OnInitialize Handler
function BugReportWindow.Initialize()       
    RegisterWindowData(WindowData.BugReport.Type,0)
    
    -- Label Text

    WindowUtils.SetWindowTitle("BugReportWindow", GetStringFromTid(BugReportWindow.TID.Bug) )

	ButtonSetText( "BugReportWindowReportSubmit", GetStringFromTid(BugReportWindow.TID.Submit) )
	ButtonSetText( "BugReportWindowReportClear", GetStringFromTid(BugReportWindow.TID.Clear) )

	LabelSetText( "BugReportTypesLabel", GetStringFromTid(BugReportWindow.TID.Select) )
    LabelSetText( "BugReportWindowLabel", GetStringFromTid(BugReportWindow.TID.Description) )

	for i = 1, BugReportWindow.Size  do
		LabelSetText("BugReportType"..i.."Label", WindowData.BugReport[i].flagName )
	end

    for index = 1, BugReportWindow.Size  do
        ButtonSetStayDownFlag( "BugReportType"..index.."Button", true )
    end
    
    BugReportWindow.OnClear();
end

-- OnUpdate Handler
function BugReportWindow.Update( timePassed )
end

-- OnShutdown Handler
function BugReportWindow.Shutdown()
	UnregisterWindowData(WindowData.BugReport.Type,0)
end


function BugReportWindow.Hide()
    ToggleWindowByName( "BugReportWindow", "", nil, BugReportWindow.OnOpen, BugReportWindow.OnClose )
end

function BugReportWindow.OnOpen()
    WindowAssignFocus( "BugReportWindowReportBoxText", true )
end

function BugReportWindow.OnClose()
    WindowAssignFocus( "BugReportWindowReportBoxText", false )
end

function BugReportWindow.OnSelectBugType()
    local type = WindowGetId(SystemData.ActiveWindow.name) 
    BugReportWindow.SelectBugType( type )
end

function BugReportWindow.SelectBugType( type )

    BugReportWindow.selectedType = type

    for index = 1, BugReportWindow.Size  do
        ButtonSetPressedFlag( "BugReportType"..index.."Button", BugReportWindow.selectedType == index )
    end

end

function BugReportWindow.OnSubmit() 
    --Debug.PrintToDebugConsole(L"Reporting Bug: Type="..BugReportWindow.selectedType..L", Text="..BugReportWindowReportBoxText.Text )
    
	SendBugReport( BugReportWindow.selectedType, BugReportWindowReportBoxText.Text )
	BugReportWindow.OnClear()
    BugReportWindow.Hide()
    
	local bugWindow =
	{
		titleTid = BugReportWindow.TID.Bug,  --"Bug Report"
		bodyTid = BugReportWindow.TID.Sent,	--"Your bug has been sent"
		windowName = "BugReportWindow",
	}
			
	UO_StandardDialog.CreateDialog(bugWindow)
   
end

function BugReportWindow.OnClear()
--     Debug.PrintToDebugConsole(L"PLayer has press Onclear" )
    BugReportWindow.SelectBugType( BugReportWindow.bugTypes.BUG_OTHER )
    TextEditBoxSetText( "BugReportWindowReportBoxText", L"" )
end
