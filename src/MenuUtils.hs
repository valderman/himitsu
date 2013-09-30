module MenuUtils where
import Graphics.UI.Gtk

-- | Add an item to a menu.
addItem :: String -> Menu -> IO () -> IO ()
addItem label m callback = do
  i <- menuItemNewWithLabel label
  menuShellAppend m i
  i `on` menuItemActivate $ callback
  widgetShow i
