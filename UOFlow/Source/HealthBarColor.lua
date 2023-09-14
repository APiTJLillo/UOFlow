----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

HealthBarColor = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

HealthBarColor.HealthVisualState = { Default = 1, Poison = 2, Cursed = 3 }
HealthBarColor.BarColor = {}
HealthBarColor.BarColor[HealthBarColor.HealthVisualState.Default] = { r =255 , g =0, b= 0} --Red
HealthBarColor.BarColor[HealthBarColor.HealthVisualState.Poison] = { r =0 , g =255, b=0}	--Green
HealthBarColor.BarColor[HealthBarColor.HealthVisualState.Cursed] = { r = 255, g =255, b=0 }	--Yellow
----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function HealthBarColor.UpdateHealthBarColor(windowTintName, visualStateId)
	hue = HealthBarColor.BarColor[visualStateId+1]
	WindowSetTintColor(windowTintName,hue.r, hue.g, hue.b)		
end

