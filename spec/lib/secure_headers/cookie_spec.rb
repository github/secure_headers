require 'spec_helper'

module SecureHeaders
  describe Cookie do
    let(:raw_cookie) { "_session=thisisatest" }

    it "does not tamper with cookies when unconfigured" do
      cookie = Cookie.new(raw_cookie, {})
      expect(cookie.to_s).to eq(raw_cookie)
    end

    it "preserves existing attributes" do
      cookie = Cookie.new("_session=thisisatest; secure", secure: true)
      expect(cookie.to_s).to match(Cookie::SECURE_REGEXP)
    end

    it "prevents duplicate flagging of attributes" do
      cookie = Cookie.new("_session=thisisatest; secure", secure: true)
      expect(cookie.to_s.scan(/secure/i).count).to eq(1)
    end

    context "Secure cookies" do
      context "when configured with a boolean" do
        it "flags cookies as Secure" do
          cookie = Cookie.new(raw_cookie, secure: true)
          expect(cookie.to_s).to match(Cookie::SECURE_REGEXP)
        end
      end

      context "when configured with a Hash" do
        it "flags cookies as Secure when whitelisted" do
          cookie = Cookie.new(raw_cookie, secure: { only: ["_session"]})
          expect(cookie.to_s).to match(Cookie::SECURE_REGEXP)
        end

        it "does not flag cookies as Secure when excluded" do
          cookie = Cookie.new(raw_cookie, secure: { except: ["_session"] })
          expect(cookie.to_s).not_to match(Cookie::SECURE_REGEXP)
        end
      end
    end

    context "HttpOnly cookies" do
      context "when configured with a boolean" do
        it "flags cookies as HttpOnly" do
          cookie = Cookie.new(raw_cookie, httponly: true)
          expect(cookie.to_s).to match(Cookie::HTTPONLY_REGEXP)
        end
      end

      context "when configured with a Hash" do
        it "flags cookies as HttpOnly when whitelisted" do
          cookie = Cookie.new(raw_cookie, httponly: { only: ["_session"]})
          expect(cookie.to_s).to match(Cookie::HTTPONLY_REGEXP)
        end

        it "does not flag cookies as HttpOnly when excluded" do
          cookie = Cookie.new(raw_cookie, httponly: { except: ["_session"] })
          expect(cookie.to_s).not_to match(Cookie::HTTPONLY_REGEXP)
        end
      end
    end

    context "SameSite cookies" do
      context "when configured with a boolean" do
        it "flags cookies as SameSite" do
          cookie = Cookie.new(raw_cookie, samesite: true)
          expect(cookie.to_s).to match(Cookie::SAMESITE_REGEXP)
        end
      end

      context "when configured with a Hash" do
        it "flags SameSite=Lax" do
          cookie = Cookie.new(raw_cookie, samesite: { lax: { only: ["_session"] } })
          expect(cookie.to_s).to match(Cookie::SAMESITE_LAX_REGEXP)
        end

        it "does not flag cookies as SameSite=Lax when excluded" do
          cookie = Cookie.new(raw_cookie, samesite: { lax: { except: ["_session"] } })
          expect(cookie.to_s).not_to match(Cookie::SAMESITE_LAX_REGEXP)
        end

        it "flags SameSite=Strict" do
          cookie = Cookie.new(raw_cookie, samesite: { strict: { only: ["_session"] } })
          expect(cookie.to_s).to match(Cookie::SAMESITE_STRICT_REGEXP)
        end

        it "does not flag cookies as SameSite=Strict when excluded" do
          cookie = Cookie.new(raw_cookie, samesite: { strict: { except: ["_session"] } })
          expect(cookie.to_s).not_to match(Cookie::SAMESITE_STRICT_REGEXP)
        end

        it "flags properly when both lax and strict are configured" do
          cookie = Cookie.new(raw_cookie, samesite: { strict: { only: ["_session"] }, lax: { only: ["_additional_session"] } })
          expect(cookie.to_s).to match(Cookie::SAMESITE_STRICT_REGEXP)
        end
      end
    end
  end

  context "with an invalid configuration" do
    it "raises an exception when not configured with a Hash" do
      expect do
        Cookie.validate_config!("configuration")
      end.to raise_error(CookiesConfigError)
    end

    it "raises an exception when configured without a boolean/Hash" do
      expect do
        Cookie.validate_config!(secure: "true")
      end.to raise_error(CookiesConfigError)
    end

    it "raises an exception when both only and except filters are provided" do
      expect do
        Cookie.validate_config!(secure: { only: [], except: [] })
      end.to raise_error(CookiesConfigError)
    end

    it "raises an exception when both only and except filters are provided to SameSite configurations" do
      expect do
        Cookie.validate_config!(samesite: { lax: { only: [], except: [] } })
      end.to raise_error(CookiesConfigError)
    end
  end
end
