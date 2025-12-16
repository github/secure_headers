
describe Growl do
  
  describe "#installed?" do
    it "should check if growlnotify is available" do
      Growl.should be_installed
    end
  end
  
  describe "#version" do
    it "should return only the version triple" do
      Growl.version.should match(/\d+\.\d+\.\d+/)
    end
  end
  
  before :each do
    @growl = Growl.new
    @growl.message = 'Hello World'
  end
  
  describe "#notify" do
    it "should accept a block, running immediately after" do
      Growl.notify { |n| n.message = 'Invoked via Growl' }.should be_true
    end
    
    it "should accept a hash" do
      Growl.notify('Invoked via Growl with hash', :icon => 'jpeg', :title => 'Growl').should be_true
    end
    
    it "should return nil when not installed" do
      Growl.stub!(:installed?).and_return(false)
      Growl.new.should be_nil
      lambda { Growl.notify 'I should never show :)' }.should_not raise_error
    end
  end
  
  %w( ok info warning error ).each do |type|
    describe "#notify_#{type}" do
      it "should display #{type} notifications" do
        Growl.send(:"notify_#{type}", "Hello", :title => type).should be_true
      end
    end
  end
  
  describe "#run" do
    it "should fail when no message is present" do
      lambda { Growl.new.run }.should raise_error(Growl::Error, /message required/)
    end
    
    it "should execute a growl notification" do
      @growl.run.should be_true
    end
  end
  
  describe "#sticky!" do
    it "should make a notification stick until explicitly closed" do
      @growl.sticky = false
      @growl.should_not be_sticky
      @growl.sticky!
      @growl.should be_sticky
      @growl.message = 'Im Sticky'
      @growl.run.should be_true
    end
  end
  
  describe "#name" do
    it "should set the application name" do
      @growl.name = 'Ruby'
      @growl.run.should be_true
    end
  end
  
  describe "#title" do
    it "should add a title" do
      @growl.title = 'Im a title'
      @growl.message = 'I am not a title'
      @growl.run.should be_true
    end
  end
  
  describe "#appIcon" do
    it "should use an application for the icon" do
      @growl.appIcon = 'Safari'
      @growl.message = 'Safari icon'
      @growl.run.should be_true
    end
  end
  
  describe "#iconpath" do
    it "should use a path for the icon" do
      @growl.iconpath = fixture 'icon.icns'
      @growl.message = 'Custom icon'
      @growl.run.should be_true
    end
  end
  
  describe "#icon" do
    it "should use an icon based on a file type" do
      @growl.icon = 'jpeg'
      @growl.message = 'Jpeg Icon'
      @growl.run.should be_true
    end
    
    it "should allow symbols" do
      @growl.icon = :jpeg
      @growl.message = 'Jpeg icon with symbol'
      @growl.run.should be_true
    end
  end
  
  describe "#image" do
    it "should use an image path for the 'icon'" do
      @growl.image = fixture 'image.png'
      @growl.message = 'Image as icon'
      @growl.run.should be_true
    end
  end
  
end