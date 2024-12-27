----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

ChatSettings = {}

ChatSettings.Channels = {}
ChatSettings.ChannelSwitches = {}

----------------------------------------------------------------
-- Saved Variables
----------------------------------------------------------------

ChatSettings.ChannelColors = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

local function SwitchText( switch, replace )
    return { commands = switch, replacement = replace }
end

local function BuildSlashCommands( commandStr )
    local commandTable = {};
    local commandList = WStringSplit( commandStr );
    
    for val, cmd in pairs(commandList) do
        if ( cmd ~= L"" ) then
            commandTable[ cmd..L" " ] = 1;
        end
    end
    
    return commandTable;
end

local function ChannelColor( red, green, blue )
    return { r = red, g = green, b = blue }
end

local function ChatChannel( iname, iid, ilogName, ionChat, ionJournal, ionAlways, iColor, iswitchTextIdx, icmd )
    local newChannel = 
    {
        name         = iname,
        id           = iid,
        logName      = ilogName,
        isOnChat     = ionChat,
        isOnJournal  = ionJournal,
        isOnAlways	 = ionAlways,
        defaultColor = iColor,
    };
   

    if ( iswitchTextIdx and icmd ) then
        newChannel.slashCmds    = BuildSlashCommands( ChatSettings.ChannelSwitches[iswitchTextIdx].commands );
        newChannel.labelText    = ChatSettings.ChannelSwitches[iswitchTextIdx].replacement;
        newChannel.serverCmd    = icmd;
    end

    return newChannel;
end

local function Font( iname, iid, idefault, ishownName )
    local newChannel = 
    {
        fontName         = iname,
        id           = iid,
        isDefault    = idefault,
        shownName    = ishownName,
    };

    return newChannel;
end

----------------------------------------------------------------
-- ChatSettings Functions
----------------------------------------------------------------

function ChatSettings.SetupChannels()

    ChatSettings.ChannelSwitches = {}
    ChatSettings.ChannelSwitches[ SystemData.ChatLogFilters.SAY ]          = SwitchText( L"/s ", L"[SAY]:" )
    ChatSettings.ChannelSwitches[ SystemData.ChatLogFilters.WHISPER ]      = SwitchText( L"/w ", L"[WHISPER]:" )
    ChatSettings.ChannelSwitches[ SystemData.ChatLogFilters.PARTY ]        = SwitchText( L"/p ", L"[PARTY]:" )
    ChatSettings.ChannelSwitches[ SystemData.ChatLogFilters.GUILD ]        = SwitchText( L"/g ", L"[GUILD]:" )
    ChatSettings.ChannelSwitches[ SystemData.ChatLogFilters.ALLIANCE ]     = SwitchText( L"/a ", L"[ALLIANCE]:" )
    ChatSettings.ChannelSwitches[ SystemData.ChatLogFilters.EMOTE ]        = SwitchText( L"/e", L"[EMOTE]:" )
    ChatSettings.ChannelSwitches[ SystemData.ChatLogFilters.YELL ]         = SwitchText( L"/y", L"[YELL]:" )
    ChatSettings.ChannelSwitches[ SystemData.ChatLogFilters.GM ]           = SwitchText( L"/gm ", L"[GM]:" )
    ChatSettings.ChannelSwitches[ SystemData.ChatLogFilters.CUSTOM ]       = SwitchText( L"/c ", L"[CHAT]:" )
    ChatSettings.ChannelSwitches[ SystemData.ChatLogFilters.GLOBAL_CHAT]   = SwitchText( L"/x ", L"[CHAT]:" )
    
    ChatSettings.Channels = {}
    --                                                                              Channel Name       Channel Id                                    Log Name    Default (Chat)  Default (Journal)    AlwaysOn		Default Color                   ChannelSwitches id                      Channel commands (what gets sent to the server to echo the text.)
    ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    ChatSettings.Channels[ SystemData.ChatLogFilters.SAY ]           = ChatChannel( L"Say",            SystemData.ChatLogFilters.SAY,                "Chat",     false,          true,                false,		ChannelColor(215, 215, 1),      SystemData.ChatLogFilters.SAY,          L"/say" )
    ChatSettings.Channels[ SystemData.ChatLogFilters.WHISPER ]       = ChatChannel( L"Whisper",        SystemData.ChatLogFilters.WHISPER,            "Chat",     false,          true,                false,		ChannelColor(215, 215, 1),      SystemData.ChatLogFilters.WHISPER,      L"/tell" )
    ChatSettings.Channels[ SystemData.ChatLogFilters.PARTY ]         = ChatChannel( L"Party",          SystemData.ChatLogFilters.PARTY,              "Chat",     true,           true,                false,		ChannelColor(56, 191, 40),      SystemData.ChatLogFilters.PARTY,        L"/party" )
    ChatSettings.Channels[ SystemData.ChatLogFilters.GUILD ]         = ChatChannel( L"Guild",          SystemData.ChatLogFilters.GUILD,              "Chat",     true,           true,                false,		ChannelColor(96, 231, 0),       SystemData.ChatLogFilters.GUILD,        L"/guild" )
    ChatSettings.Channels[ SystemData.ChatLogFilters.ALLIANCE ]      = ChatChannel( L"Alliance",       SystemData.ChatLogFilters.ALLIANCE,           "Chat",     true,           true,                false,		ChannelColor(48, 215, 231),     SystemData.ChatLogFilters.ALLIANCE,     L"/alliance" )    
    ChatSettings.Channels[ SystemData.ChatLogFilters.EMOTE ]         = ChatChannel( L"Emote",          SystemData.ChatLogFilters.EMOTE,              "Chat",     false,          true,                false,		ChannelColor(215, 215, 1),      SystemData.ChatLogFilters.EMOTE,        L"/emote" )
    ChatSettings.Channels[ SystemData.ChatLogFilters.YELL ]          = ChatChannel( L"Yell",           SystemData.ChatLogFilters.YELL,               "Chat",     false,          true,                false,		ChannelColor(215, 215, 1),      SystemData.ChatLogFilters.YELL,         L"/yell" )
    ChatSettings.Channels[ SystemData.ChatLogFilters.SYSTEM ]        = ChatChannel( L"System",         SystemData.ChatLogFilters.SYSTEM,             "Chat",     true,           true,                true,		ChannelColor(255, 255, 255) )    
    ChatSettings.Channels[ SystemData.ChatLogFilters.PRIVATE ]       = ChatChannel( L"Private",        SystemData.ChatLogFilters.PRIVATE,            "Chat",     true,           true,                false,		ChannelColor(207, 56, 223) )
    ChatSettings.Channels[ SystemData.ChatLogFilters.CUSTOM ]        = ChatChannel( L"Chat (Channel)", SystemData.ChatLogFilters.CUSTOM,             "Chat",     true,           true,                false,		ChannelColor(75, 120, 230),     SystemData.ChatLogFilters.CUSTOM,       L"/chat" )
    ChatSettings.Channels[ SystemData.ChatLogFilters.GESTURE ]       = ChatChannel( L"Gesture",        SystemData.ChatLogFilters.GESTURE,            "Chat",     true,           true,                false,		ChannelColor(215, 215, 1) )
    ChatSettings.Channels[ SystemData.ChatLogFilters.GM ]            = ChatChannel( L"GM",			   SystemData.ChatLogFilters.GM,                 "Chat",     true,           true,                true,			ChannelColor(232, 48, 88),      SystemData.ChatLogFilters.GM,           L"/gm" )
    ChatSettings.Channels[ SystemData.ChatLogFilters.GLOBAL_CHAT]    = ChatChannel( L"GChat",          SystemData.ChatLogFilters.GLOBAL_CHAT,         "Chat",     true,           true,                false,       ChannelColor(75, 120, 230),      SystemData.ChatLogFilters.GLOBAL_CHAT,  L"/x" )
   
    

    ChatSettings.Ordering = {
        --SystemData.ChatLogFilters.SYSTEM,
        SystemData.ChatLogFilters.SAY,
        SystemData.ChatLogFilters.PRIVATE,
        SystemData.ChatLogFilters.CUSTOM,
        SystemData.ChatLogFilters.EMOTE,
        SystemData.ChatLogFilters.GESTURE,
        SystemData.ChatLogFilters.WHISPER,
        SystemData.ChatLogFilters.YELL,
        SystemData.ChatLogFilters.PARTY,
        SystemData.ChatLogFilters.GUILD,
        SystemData.ChatLogFilters.ALLIANCE,
        SystemData.ChatLogFilters.GM,
        SystemData.ChatLogFilters.GLOBAL_CHAT,
    }
    
    ChatSettings.Colors = {
        --{r=235, g=235, b=235, id=1},
        {r=32, g=134, b=229, id=2},
        {r=29, g=217, b=33, id=3},
        {r=178, g=255, b=116, id=4},
        {r=239, g=221, b=19, id=5},
        {r=190, g=190, b=190, id=6},
        {r=255, g=255, b=1, id=7},
        {r=144, g=237, b=250, id=8},
        {r=238, g=113, b=21, id=9},
        {r=18, g=202, b=209, id=10},
        {r=231, g=189, b=115, id=11},
        {r=55, g=65, b=248, id=12},
        {r=32, g=224, b=32, id=13},
        {r=251, g=236, b=3, id=14},
        {r=217, g=28, b=28, id=15},
        {r=238, g=113, b=21, id=16},
        {r=235, g=213, b=135, id=17},
        {r=255, g=39, b=39, id=18},
        {r=255, g=168, b=5, id=19},
        {r=195, g=54, b=150, id=20},
        {r=1, g=167, b=167, id=21},
        {r=55, g=65, b=248, id=22},
        {r=110, g=110, b=110, id=23},
        {r=239, g=221, b=19, id=24},
        {r=1, g=167, b=165, id=25},
    }       
    
end

function ChatSettings.SetupChannelColorDefaults( resetAll )

    if ( resetAll ) then
        ChatSettings.ChannelColors = {}
    end

    for key, value in pairs( ChatSettings.Channels ) do
        if ( resetAll or ChatSettings.ChannelColors[ key ] == nil ) then
            ChatSettings.ChannelColors[ key ] = value.defaultColor
        end
    end

end

-- DAB TODO: Add chat fonts!
function ChatSettings.SetupFontDefaults()
    ChatSettings.Fonts = {}
    --                               name of font     id  default  name to be shown
    ChatSettings.Fonts[1] = Font( "UO_Chat_UMEGOTHIC_15pt", 1, false, "Gothic - Small (Unicode)" )
    ChatSettings.Fonts[2] = Font( "UO_Chat_UMEGOTHIC_18pt", 1, false, "Gothic - Medium (Unicode)" )
    ChatSettings.Fonts[3] = Font( "UO_Chat_UMEGOTHIC_21pt", 1, false, "Gothic - Large (Unicode)" )
    ChatSettings.Fonts[4] = Font( "UO_Chat_ArialUni_15pt", 1, false, "Arial - Small (Unicode)" )
    ChatSettings.Fonts[5] = Font( "UO_Chat_ArialUni_18pt", 1, false, "Arial - Medium (Unicode)" )
    ChatSettings.Fonts[6] = Font( "UO_Chat_ArialUni_21pt", 1, false, "Arial - Large (Unicode)" )    
    
    if( SystemData.Settings.Language.type == SystemData.Settings.Language.LANGUAGE_ENU ) then
		ChatSettings.Fonts[7] = Font( "UO_Chat_MyriadPro_15pt", 1, false, "Myriad Pro - Small" )
		ChatSettings.Fonts[8] = Font( "UO_Chat_MyriadPro_18pt", 1, false, "Myriad Pro - Medium" )
		ChatSettings.Fonts[9] = Font( "UO_Chat_MyriadPro_21pt", 1, false, "Myriad Pro - Large" )    
		ChatSettings.Fonts[10] = Font( "UO_Chat_Helvetica_15pt", 1, false, "Helvetica - Small" )
		ChatSettings.Fonts[11] = Font( "UO_Chat_Helvetica_18pt", 1, false, "Helvetica - Medium" )
		ChatSettings.Fonts[12] = Font( "UO_Chat_Helvetica_21pt", 1, false, "Helvetica - Large" )
	end
	
    ChatSettings.Fonts[13] = Font( "Runic", 3, false, "Runic - Large" )
    
end

----------------------------------------------------------------
-- Initialization
----------------------------------------------------------------

ChatSettings.SetupChannels()
ChatSettings.SetupChannelColorDefaults( true )
ChatSettings.SetupFontDefaults()
